# Flow Log Analyzer

## Overview

The Flow Log Analyzer is a Python utility designed to parse and analyze network flow logs. It helps identify and categorize network traffic based on destination ports, protocols, and predefined tags.

## Features

- Parse network flow logs
- Match destination ports and protocols to predefined tags 
- Support for case-insensitive protocol matching
- Flexible configuration with optional headers
- Generates comprehensive analysis reports

## Requirements

- Python 3.7+
- Standard Python libraries (collections, logging, sys)

## Installation

1. Clone the repository
```bash
git clone https://github.com/nnighojk-source/Illumio_coding_challenge.git
cd Illumio_coding_challenge
```

2. Ensure you have Python installed
```bash
python3 --version 
```

## Usage

### Basic Command
```bash
python flow_analyzer.py <lookup_table_file> <log_file> <output_file> [--no-headers]
```
The --no-headers flag is an optional command that indicates a file lacks headers

### Lookup Table Format
The lookup table is a CSV file with three columns:
- `dstport`: Destination port number
- `protocol`: Protocol name (case-insensitive) 
- `tag`: Custom tag for the port/protocol combination

Example lookup table:
```
dstport,protocol,tag
80,tcp,web
443,tcp,ssl
22,ssh,ssh
```

### Log File Format  
- Space-delimited log files
- Minimum of 14 fields
- Destination port in 7th field (index 6)
- Protocol in 8th field (index 7)

## Assumptions and Constraints

### Input File Assumptions
1. **Lookup Table**
   - Comma-separated CSV format
   - Case-insensitive protocol matching
   - Protocols must match predefined protocol names

2. **Log File**
   - Space-delimited format
   - Exactly 14 fields
   - Consistent field positions for port and protocol

### Protocol Mapping
- Protocol numbers in log files are converted to protocol names
- Supports conversion for common protocols (TCP, UDP, ICMP, etc.)
- Uses IANA Protocol Numbers registry for mapping

### Performance and Scalability 
- Designed for moderate-sized log files
- Entire files are loaded into memory
- May not be suitable for extremely large log files

## Testing Approach

### Test Cases
Use the provided `test_cases.py` script to generate a log file with test cases:
```bash
python test_cases.py
```

### Key Test Scenarios
- Parsing lookup tables with and without headers
- Log parsing with different protocol representations
- Untagged port detection 
- Multiple tag assignment

### Test Limitations
- Uses synthetic, controlled test data
- No performance testing for large files
- Does not simulate all real-world network log complexities 

## Logging

The application uses Python's logging module to provide:
- Analysis progress tracking
- Warning messages for processing issues
- Error notifications

## Protocol Mapping Source

Protocol numbers and names are sourced from the [IANA Protocol Numbers Registry](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)

## Error Handling

- Skips malformed log lines
- Provides warning messages for processing errors
- Supports files with or without headers

## Sample Workflow

1. Prepare a lookup table with protocol names
2. Prepare a log file with space-delimited data 
3. Run `python test_cases.py` to generate test cases
4. Run the analyzer
5. Review the generated output CSV
