# UserAssist Parser for Windows Systems

This tool parses UserAssist information from Windows systems (7/8/10/11) either from live registry data or from an offline NTUSER.dat file. It parses information regarding program execution such as program names, run count, focus count, focus time and last executed.

## Features

- **Live Parsing**: Extracts UserAssist data directly from the live registry.
- **Offline Parsing**: Parses UserAssist data from an offline NTUSER.dat file.
- **CSV Export**: Writes parsed data into a CSV file for further analysis.

## Setup

- Python 3.x installed on your system.
- Required Python packages can be installed using `pip`: 
- use command: "pip install regipy"

## Command Line Arguments [Command Line Arguments](#command-line-arguments)

The tool `main.py` supports the following command line arguments:

### Help

To display the help message and see all available options, use `-h` or `--help`:

```bash
python main.py -h
```

### Live Parsing

To parse UserAssist data directly from the live registry, use `--live`:

```bash
python main.py --live
```

### Offline Parsing

To parse UserAssist data from an offline NTUSER.dat file, use `--offline` followed by the path to the file:

```bash
python main.py --offline path/to/ntuser.dat
```

### Output CSV

To save the parsed data to a CSV file, use `--output-csv` followed by the desired file name:

```bash
python main.py --live --output-csv userassist_data.csv
```

### Show Output in Terminal

To print the parsed output to the command line, use `--show-output`:

```bash
python main.py --offline path/to/ntuser.dat --show-output
```

## Usage of the .EXE File (usserassist_parser.exe)

For direct execution of the compiled executable, follow the instructions under [Command Line Arguments](#command-line-arguments)

### Sample usage

```bash
userassist_parser.exe -h
```

```bash
userassist_parser.exe --live
```

```bash
userassist_parser.exe --offline path/to/ntuser.dat
```
