# LibCTT - Library Converter & Text Tool

LibCTT is a cross-platform command-line tool to convert compiled binary libraries (`.dll`, `.so`, `.lib`, `.a`) into detailed, human-readable TXT reports.  
It helps you inspect, audit, and document dynamic and static libraries in Windows, Linux, and macOS environments.

---

## Features

- **Format Detection:**  
  Automatically detects ELF, PE, and AR (static library) formats.
- **Symbol Extraction:**  
  Lists exported symbols and functions using platform tools (`objdump`, `dumpbin`, `readelf`, `nm`, `lib.exe`).
- **Disassembly Preview:**  
  Includes up to 2000 lines of disassembly for supported types.
- **Static Library Member Listing:**  
  Lists member objects in `.lib`/`.a` archives (Windows only, needs `lib.exe`).
- **MINGW64 Support:**  
  Handles `.so` files compiled with MINGW64 on Windows.
- **Robust Output:**  
  Timezone-aware UTC timestamps, file size limits, partial outputs for large files.
- **Cross-Platform:**  
  Works on Linux, Windows, macOS (tool availability may vary).

---

## Installation

### Requirements

- **Python 3.6+**
- Platform binary tools:
  - Linux/macOS: `objdump`, `readelf`, `nm`
  - Windows: `dumpbin`, `lib.exe` (Visual Studio), `objdump` (mingw64, optional)

### Download

Clone this repo or download `libctt.py` and `README.md`:

```bash
git clone https://github.com/YOUR_GITHUB_USER/libctt.git
cd libctt
```

### Quick Start

```bash
python libctt.py yourlib.dll yourlib.so yourlib.lib
```

---

## Usage

### Basic Conversion

```bash
python libctt.py myfile.so myfile.dll myfile.lib
```

### Custom Output Directory

```bash
python libctt.py myfile.dll -o ./reports/
```

### Limit Disassembly Output

```bash
python libctt.py myfile.so --limit-disasm 1000
```

### Change Maximum File Size (MB)

```bash
python libctt.py myfile.so --max-size 50
```

### Full CLI Help

```bash
python libctt.py -h
```

Output:

```text
usage: libctt.py [-h] [-o OUTPUT_DIR] [--max-size MAX_SIZE] [--limit-disasm LIMIT_DISASM] files [files ...]

LibCTT - Binary Library to Human-Readable TXT Converter

positional arguments:
  files                 Input library files (.so, .dll, .lib, .a)

options:
  -h, --help            show this help message and exit
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Directory to save reports (default: same as input file)
  --max-size MAX_SIZE   Max file size in MB (default: 100)
  --limit-disasm LIMIT_DISASM
                        Max lines of disassembly (default: 2000)
```

---

## Output

For each input file, LibCTT generates a TXT report (`<basename>_libctt.txt`) containing:

- **Header:** Timestamp, input file, size, detected format.
- **Format Details:** ELF/PE header info, archive members, etc.
- **Symbols/Exports:** List of exported symbols/functions.
- **Disassembly (Partial):** Up to N lines (default: 2000).
- **Warnings:** Exceeds size limit, missing tools, truncated output.

Example:

```
LibCTT Report
========================================
Generated: 2025-10-05T22:00:00+00:00 UTC
Input file: mylib.so
File size: 1.23MB

Detected kind: ELF

ELF Header:
  class: ELF64
  endian: LittleEndian

Symbols / Exports:
  Tool used: /usr/bin/readelf
  0000000000001040 FUNC    GLOBAL DEFAULT   13 main
  ...

Disassembly (partial):
  Tool used: /usr/bin/objdump
  0000000000001040 <main>:
    1040: 55                    push   %rbp
    1041: 48 89 e5              mov    %rsp,%rbp
    ...
  ...disassembly truncated (2000 lines total)
```

---

## Documentation

### Supported Formats

- **ELF:** `.so` (Linux, macOS, MINGW64)
- **PE:** `.dll` (Windows, MINGW64), `.exe`
- **AR:** `.lib`, `.a` (static archives)

### Tools Used

| Format | Tool(s) Used                | Output                    |
|--------|-----------------------------|---------------------------|
| ELF    | objdump, readelf, nm        | Disassembly, symbols      |
| PE     | dumpbin, objdump            | Disassembly, exports      |
| AR/lib | lib.exe (Windows only)      | Archive member listing    |

### Limitations

- Requires platform tools in your PATH (see above).
- Large files (>100MB by default) are skipped for safety.
- Disassembly/symbol output truncated for large binaries.
- Static library member extraction only works on Windows.

---

## FAQ

**Q:** Why does LibCTT say "No disassembler found on PATH"?  
**A:** Make sure `objdump`, `dumpbin`, or `readelf` are installed and available in your system PATH.

**Q:** Can I use LibCTT on macOS?  
**A:** Yes, for ELF and AR files, provided you have compatible tools (e.g., `gobjdump`, `nm`).

**Q:** How do I process multiple files at once?  
**A:** Specify them on the command line:  
`python libctt.py file1.dll file2.so file3.lib`

---

## Contributing

Pull requests and issues are welcome!  
- Open issues for bugs or feature requests.
- Fork and submit PRs for enhancements or new formats.

### Development

- The code is modular and documented.
- Add new formats or analysis tools by extending detection and extraction functions.

---

## License

AGPL License (see LICENSE file).

---

## Credits

Developed by [SSMG4](https://github.com/SSMG4) and contributors.  
Inspired by cross-platform reverse engineering tools.
