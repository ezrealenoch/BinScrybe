# BinScrybe

A comprehensive binary analysis tool that integrates multiple security analysis engines to generate detailed reports about executable files.

## Features

- Automated analysis using multiple security tools (CAPA, DIE, PE-sieve)
- Detection of malicious capabilities and suspicious features
- Identification of anti-analysis techniques
- Entropy analysis and packer detection
- Comprehensive markdown reports for easy sharing
- Process hollowing and code injection detection
- Support for various binary formats (PE, ELF, Mach-O)

## Requirements

- Python 3.6 or higher
- Windows OS (for full functionality with all tools)
- External tools:
  - CAPA: Capability detection tool from Mandiant
  - DIE (Detect It Easy): For file format identification and compiler/packer detection
  - PE-sieve: For PE file anomaly detection

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/binscrybe.git
   cd binscrybe
   ```

2. Set up the tools:
   ```
   python setup_tools.py
   ```
   This script will look for the required tools in standard locations and configure them for use with BinScrybe.

3. Download any missing tools:
   - CAPA: https://github.com/mandiant/capa/releases
   - DIE: https://github.com/horsicq/DIE-engine/releases
   - PE-sieve: https://github.com/hasherezade/pe-sieve/releases

   Place these tools in the `tools` directory or ensure they're in your PATH.

## Usage

Basic usage:
```
python binscrybe.py path/to/binary.exe
```

Options:
```
python binscrybe.py path/to/binary.exe [options]

Options:
  -o, --output FILE      Output file path (default: [binary_name]_summary.md)
  --skip-capa            Skip CAPA analysis
  --skip-die             Skip DIE analysis
  --skip-pesieve         Skip PE-sieve analysis
  --tools-dir DIR        Path to tools directory (default: tools/)
  --die-dir DIR          Path to DIE directory (default: tools/die_winxp_portable_3.10_x86/)
  --verbose              Enable verbose output
```

## Output

BinScrybe generates a comprehensive markdown report that includes:

- Basic file information (size, hashes, etc.)
- CAPA capability detection results
- DIE format, compiler, and packer detection
- PE-sieve anomaly detection
- Entropy analysis
- Threat assessment
- Detailed explanation of suspicious features

## Example

Analyzing Windows Notepad:
```
python binscrybe.py C:\Windows\notepad.exe
```

This will generate a detailed report named `notepad_summary.md`.

## Project Structure

- `binscrybe.py`: Main script
- `setup_tools.py`: Tool configuration and setup
- `tool_tester.py`: Utility for testing installed tools
- `tools/`: Directory for external analysis tools
  - `die_winxp_portable_3.10_x86/`: DIE portable version

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Mandiant](https://github.com/mandiant) for the CAPA tool
- [Horesicq](https://github.com/horsicq) for the DIE engine
- [Hasherezade](https://github.com/hasherezade) for PE-sieve 