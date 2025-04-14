# BinScrybe

A comprehensive binary analysis tool that integrates multiple security analysis engines to generate detailed reports about executable files.

> Vibe Coding my Reverse Engineering Job Away

## Features

- Automated analysis using multiple security tools (CAPA, DIE, PE-sieve)
- Detection of malicious capabilities and suspicious features
- Identification of anti-analysis techniques
- Entropy analysis and packer detection
- Comprehensive markdown reports for easy sharing
- Process hollowing and code injection detection
- Support for various binary formats (PE, ELF, Mach-O)
- **NEW**: Integration with Ghidra for visual reverse engineering

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
   git clone https://github.com/ezrealenoch/binscrybe.git
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
  -o, --output FILE      Output file path (default: output/[binary_name]_summary.md)
  --skip-capa            Skip CAPA analysis
  --skip-die             Skip DIE analysis
  --skip-pesieve         Skip PE-sieve analysis
  --tools-dir DIR        Path to tools directory (default: tools/)
  --output-dir DIR       Path to output directory (default: output/)
  --die-dir DIR          Path to DIE directory (default: tools/die_winxp_portable_3.10_x86/)
  --verbose              Enable verbose output

Ghidra Integration:
  --ghidra               Import results into Ghidra after analysis
  --ghidra-path DIR      Path to the Ghidra installation directory
  --ghidra-project DIR   Path to the Ghidra project directory
  --no-headless          Run Ghidra in GUI mode instead of headless mode
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

All output files are saved to the `output` directory by default. You can specify a different location using the `--output-dir` parameter.

## Example

Analyzing Windows Notepad:
```
python binscrybe.py C:\Windows\notepad.exe
```

This will generate a detailed report named `output/notepad_summary.md`.

## Project Structure

- `binscrybe.py`: Main script
- `setup_tools.py`: Tool configuration and setup
- `tool_tester.py`: Utility for testing installed tools
- `tools/`: Directory for external analysis tools
  - `die_winxp_portable_3.10_x86/`: DIE portable version
- `output/`: Directory for analysis results and reports
- `ghidra_integration.py`: Integration with Ghidra reverse engineering tool
- `ghidra_scripts/`: Directory containing Ghidra scripts for importing results
- `tests/`: Directory for test scripts and resources

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Mandiant](https://github.com/mandiant) for the CAPA tool
- [Horesicq](https://github.com/horsicq) for the DIE engine
- [Hasherezade](https://github.com/hasherezade) for PE-sieve

## Ghidra Integration

BinScrybe can integrate with the [Ghidra](https://ghidra-sre.org/) reverse engineering platform to provide visual exploration of analysis results.

### Requirements

- Ghidra 10.0 or later (available from https://ghidra-sre.org/)
- Java 11 or later

### Usage

To analyze a binary and import the results into Ghidra:

```
python binscrybe.py path/to/binary.exe --ghidra --ghidra-path "C:/Program Files/Ghidra"
```

This will:
1. Analyze the binary using BinScrybe
2. Import the results into Ghidra as bookmarks and comments
3. Generate a new Ghidra project with the analysis results

Alternatively, you can import just the results into Ghidra:

```
python ghidra_integration.py output/full_report.json path/to/binary.exe --ghidra-path "C:/Program Files/Ghidra"
```

### Features

The Ghidra integration provides:
- Bookmarks at addresses where capabilities were detected
- Comments with explanation of capability functionality
- Function renaming based on detected capabilities
- Better navigation and understanding of analysis results
