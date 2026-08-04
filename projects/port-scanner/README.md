# Port Scanner

A simple TCP port scanner written in Python for identifying open services on a target host.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates understanding of:

- TCP/IP networking fundamentals
- Socket programming in Python
- Command-line interface design
- Port scanning techniques

## Technologies

- Python 3.14+
- Standard library (socket, argparse)

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/port-scanner

## Usage

python3 port_scanner.py -H <TARGET> [-p <PORTS>] [-t <TIMEOUT>]

### Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| -H | --host | Target IP address or domain name (required) |
| -p | --ports | Port range or list (default: 1-1024) |
| -t | --timeout | Connection timeout in seconds (default: 1.0) |

### Examples

Scan default ports (1-1024):
python3 port_scanner.py -H scanme.nmap.org

Scan specific ports:
python3 port_scanner.py -H scanme.nmap.org -p 22,80,443

Scan a port range:
python3 port_scanner.py -H scanme.nmap.org -p 1-100

Scan with custom timeout:
python3 port_scanner.py -H scanme.nmap.org -t 0.5

## Example Output

[SCAN] Target: scanme.nmap.org
[SCAN] Ports to scan: 3
[SCAN] Timeout: 1.0s

[OPEN] Port 22 is open
[OPEN] Port 80 is open
[INFO] Port 443 is closed

[SUMMARY] Open ports: [22, 80]
[SUMMARY] Total ports scanned: 3
[SUMMARY] Total open ports: 2

## Future Improvements

- Banner grabbing for service identification
- Parallel scanning with threading
- UDP support
- JSON/CSV export
- Service detection based on port

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea