#!/usr/bin/env python3
"""
LibCTT - Library Converter & Text Tool
--------------------------------------
Converts .so, .dll, .lib files into human-readable text reports.

Features:
- Detects and parses ELF, PE, AR (static library) formats.
- Extracts symbols and disassembly with system tools (objdump, dumpbin, readelf, nm, lib.exe).
- Handles MINGW64 .so files on Windows.
- Supports static .lib member extraction.
- Timezone-aware UTC reporting.
- 100MB file size safety limit.
- Cross-platform: Linux, Windows, macOS (tool availability may vary).
"""

import os
import sys
import struct
import shutil
import subprocess
from datetime import datetime, timezone
import argparse

MAX_SIZE_MB = 100
REPORT_SUFFIX = "_libctt.txt"
DISASM_LINE_LIMIT = 2000  # max lines of disassembly included

# ------------------ Utility functions ------------------

def human_size(n):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024.0:
            return f"{n:.2f}{unit}"
        n /= 1024.0
    return f"{n:.2f}TB"

def check_file_size(path):
    size = os.path.getsize(path)
    size_mb = size / (1024 * 1024)
    return size, size_mb <= MAX_SIZE_MB

def detect_magic(path):
    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as f:
        head = f.read(0x200)
    # Magic bytes detection
    if head.startswith(b"\x7fELF"):
        return "ELF", head
    if head.startswith(b"MZ"):
        # Special case: .so compiled with MINGW64 on Windows
        if ext == ".so":
            return "MINGW64_SO", head
        return "PE", head
    if head.startswith(b"!<arch>\n"):
        return "AR", head
    return "UNKNOWN", head

def parse_elf_header(head):
    try:
        ei_class = head[4]
        ei_data = head[5]
        cls = "ELF32" if ei_class == 1 else "ELF64" if ei_class == 2 else "UnknownClass"
        endian = "LittleEndian" if ei_data == 1 else "BigEndian" if ei_data == 2 else "UnknownEndian"
        return {"class": cls, "endian": endian}
    except Exception as e:
        return {"error": f"Failed parsing ELF header: {e}"}

def parse_pe_header(head, path):
    try:
        if len(head) < 0x40:
            with open(path, "rb") as f:
                head = f.read(0x200)
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        with open(path, "rb") as f:
            f.seek(e_lfanew + 4)
            machine_bytes = f.read(2)
            if len(machine_bytes) < 2:
                return {"error": "PE header too short"}
            machine = struct.unpack("<H", machine_bytes)[0]
            machine_map = {
                0x014c: "x86 (Intel 386)",
                0x8664: "x86-64",
                0x01c0: "ARM",
                0xAA64: "ARM64 (AArch64)",
                0x01c4: "ARMv7",
            }
            return {"e_lfanew": e_lfanew, "machine": machine_map.get(machine, f"Unknown(0x{machine:04x})")}
    except Exception as e:
        return {"error": f"Failed parsing PE header: {e}"}

def find_tool(tool_names):
    for t in tool_names:
        path = shutil.which(t)
        if path:
            return path
    return None

def run_disassembler(path, kind):
    disasm_tool = None
    args = None
    if kind in ("ELF", "MINGW64_SO"):
        od = find_tool(["objdump", "gobjdump"])
        if od:
            disasm_tool = od
            args = [od, "-d", path]
    elif kind == "PE":
        dumpbin = find_tool(["dumpbin"])
        if dumpbin:
            disasm_tool = dumpbin
            args = [dumpbin, "/DISASM", path]
        else:
            od = find_tool(["objdump", "gobjdump"])
            if od:
                disasm_tool = od
                args = [od, "-d", path]
    if not disasm_tool:
        return None, "No disassembler found on PATH."
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        out = proc.stdout if proc.stdout else proc.stderr
        lines = out.splitlines()
        if len(lines) > DISASM_LINE_LIMIT:
            lines = lines[:DISASM_LINE_LIMIT] + [f"...output truncated (limit {DISASM_LINE_LIMIT} lines)..."]
        return disasm_tool, lines
    except Exception as e:
        return None, f"Failed to run disassembler {disasm_tool}: {e}"

def run_symbol_dump(path, kind):
    if kind in ("ELF", "MINGW64_SO"):
        tool = find_tool(["readelf", "nm"])
        if not tool:
            return None, "No symbol tool (readelf/nm) found on PATH."
        args = [tool, "-s", path] if os.path.basename(tool).lower().startswith("readelf") else [tool, "-D", path]
    elif kind == "PE":
        dumpbin = find_tool(["dumpbin"])
        if dumpbin:
            args = [dumpbin, "/EXPORTS", path]
        else:
            od = find_tool(["objdump", "gobjdump"])
            if od:
                args = [od, "-x", path]
            else:
                return None, "No symbol tool found (dumpbin or objdump)."
    else:
        return None, "Unknown kind for symbol dump."
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        out = proc.stdout if proc.stdout else proc.stderr
        lines = out.splitlines()
        if len(lines) > 2000:
            lines = lines[:2000] + ["...output truncated..."]
        return args[0], lines
    except Exception as e:
        return None, f"Failed to run symbol tool {args[0]}: {e}"

def run_lib_members(path):
    lib_tool = find_tool(["lib"])
    if not lib_tool:
        return None, "lib.exe not found; cannot list static .lib members."
    args = [lib_tool, "/LIST", path]
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        out = proc.stdout if proc.stdout else proc.stderr
        lines = out.splitlines()
        if len(lines) > 500:
            lines = lines[:500] + ["...members truncated..."]
        return lib_tool, lines
    except Exception as e:
        return None, f"Failed to list .lib members: {e}"

# ------------------ Report generator ------------------

def generate_report(path, outpath):
    size, ok = check_file_size(path)
    report = []
    report.append("LibCTT Report")
    report.append("=" * 40)
    report.append(f"Generated: {datetime.now(timezone.utc).isoformat()} UTC")
    report.append(f"Input file: {path}")
    report.append(f"File size: {human_size(size)}\n")

    kind, head = detect_magic(path)
    report.append(f"Detected kind: {kind}\n")

    if kind == "ELF":
        eh = parse_elf_header(head)
        report.append("ELF Header:")
        for k, v in eh.items():
            report.append(f"  {k}: {v}")
    elif kind == "MINGW64_SO":
        eh = parse_elf_header(head)
        report.append("MINGW64 .SO Header (PE inside):")
        for k, v in eh.items():
            report.append(f"  {k}: {v}")
    elif kind == "PE":
        peh = parse_pe_header(head, path)
        report.append("PE Header:")
        for k, v in peh.items():
            report.append(f"  {k}: {v}")
    elif kind == "AR":
        report.append("Archive (.a/.lib) detected.")
        tool, members = run_lib_members(path)
        if tool is None:
            report.append(f"  [!] {members}")
        else:
            report.append(f"  Tool used: {tool}")
            for line in members:
                report.append("  " + line)
    else:
        report.append("Unknown or unsupported file type.")

    report.append("")

    if not ok:
        report.append(f"File exceeds size limit of {MAX_SIZE_MB} MB. Aborting detailed analysis.")
        with open(outpath, "w", encoding="utf-8") as f:
            f.write("\n".join(report))
        return True, "size_exceeded"

    if kind not in ("AR", "UNKNOWN"):
        # Symbols
        tool, symbols = run_symbol_dump(path, kind)
        report.append("Symbols / Exports:")
        if tool is None:
            report.append(f"  [!] {symbols}")
        else:
            report.append(f"  Tool used: {tool}")
            for line in symbols[:200]:
                report.append("  " + line)
            if len(symbols) > 200:
                report.append(f"  ...symbols truncated ({len(symbols)} lines total)")

        report.append("")
        # Disassembly
        dtool, disasm = run_disassembler(path, kind)
        report.append("Disassembly (partial):")
        if dtool is None:
            report.append(f"  [!] {disasm}")
        else:
            report.append(f"  Tool used: {dtool}")
            for line in disasm[:500]:
                report.append("  " + line)
            if len(disasm) > 500:
                report.append(f"  ...disassembly truncated ({len(disasm)} lines total)")

    report.append("")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write("\n".join(report))
    return True, outpath

# ------------------ CLI & Main ------------------

def main():
    parser = argparse.ArgumentParser(
        description="LibCTT - Binary Library to Human-Readable TXT Converter",
        epilog="Supports .dll, .so, .lib, .a. Output is a TXT report. "
               "Requires system tools like objdump, dumpbin, readelf, nm, lib.exe for full features."
    )
    parser.add_argument("files", nargs="+", help="Input library files (.so, .dll, .lib, .a)")
    parser.add_argument("-o", "--output-dir", default=None, help="Directory to save reports (default: same as input file)")
    parser.add_argument("--max-size", type=int, default=MAX_SIZE_MB, help=f"Max file size in MB (default: {MAX_SIZE_MB})")
    parser.add_argument("--limit-disasm", type=int, default=DISASM_LINE_LIMIT, help=f"Max lines of disassembly (default: {DISASM_LINE_LIMIT})")
    args = parser.parse_args()

    def main():
    global MAX_SIZE_MB, DISASM_LINE_LIMIT
    parser = argparse.ArgumentParser(
        description="LibCTT - Binary Library to Human-Readable TXT Converter",
        epilog="Supports .dll, .so, .lib, .a. Output is a TXT report. "
               "Requires system tools like objdump, dumpbin, readelf, nm, lib.exe for full features."
    )
    parser.add_argument("files", nargs="+", help="Input library files (.so, .dll, .lib, .a)")
    parser.add_argument("-o", "--output-dir", default=None, help="Directory to save reports (default: same as input file)")
    parser.add_argument("--max-size", type=int, default=MAX_SIZE_MB, help=f"Max file size in MB (default: {MAX_SIZE_MB})")
    parser.add_argument("--limit-disasm", type=int, default=DISASM_LINE_LIMIT, help=f"Max lines of disassembly (default: {DISASM_LINE_LIMIT})")
    args = parser.parse_args()

    # Allow override of globals for advanced users
    MAX_SIZE_MB = args.max_size
    DISASM_LINE_LIMIT = args.limit_disasm

    for path in args.files:
        if not os.path.isfile(path):
            print(f"Skipping non-file: {path}")
            continue
        base = os.path.basename(path)
        outdir = args.output_dir if args.output_dir else os.path.dirname(path)
        outpath = os.path.join(outdir, base + REPORT_SUFFIX)
        try:
            ok, info = generate_report(path, outpath)
            if ok:
                print(f"Report for {path} -> {outpath} ({info})")
            else:
                print(f"Failed to process {path}: {info}")
        except Exception as e:
            print(f"Error processing {path}: {e}")

if __name__ == "__main__":
    main()
