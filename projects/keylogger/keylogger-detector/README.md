# Keylogger Detector

Detects keyloggers and spyware by analyzing running processes, file contents, and network connections.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates:

- Process analysis
- File content scanning
- Network connection monitoring
- Risk assessment
- Report generation

## Technologies

- Python 3.14+
- psutil
- Regex
- JSON

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/keylogger/keylogger-detector

pip install -r requirements.txt

## Usage

python3 detector.py [OPTIONS]

### Options

| Option | Description |
|--------|-------------|
| -v, --verbose | Enable verbose output |
| -w, --whitelist FILE | File with process names to ignore (one per line) |
| --interval SECONDS | Run continuously, scanning every N seconds |

> Note: the detector uses **behavioral** analysis (suspicious imports such as
> pynput/keyboard/evdev, access to input devices under `/dev/input`, and active
> network connections) rather than a fixed list of process names.

## Detection Criteria

### Suspicious Processes

- Known keylogger names (keylog.exe, hook.exe, etc.)
- Keywords: keylog, hook, keyboard, capture, spy
- Processes running from temporary directories

### Suspicious Files

- Code patterns: GetKeyState, SetWindowsHookEx, WH_KEYBOARD
- Suspicious keywords in file content
- Excludes: node_modules, __pycache__, system logs

### Suspicious Network Connections

- Processes with keylogger-like behavior and external connections
- Established connections from suspicious processes

## Example Output

========================================
  Keylogger Detector
========================================
  Scanning for keyloggers and spyware
========================================

[SCAN] Processes...
  [HIGH] Known keylogger process: keylog.exe
  [MEDIUM] Suspicious keyword 'hook' in process: keyboard_hook.exe

[SCAN] Files...
  [HIGH] Found keylogger code in: /tmp/keylog.py

[SCAN] Network connections...
  [HIGH] Suspicious process keylog.exe has network connection to 192.168.1.100:8080

=================================================
[REPORT] Keylogger Detection
=================================================
  Risk Score: 75/100
  Risk Level: HIGH
  Total Findings: 3
    Processes: 1
    Files: 1
    Connections: 1

  Top Findings:
    [HIGH] Known keylogger process: keylog.exe
    [HIGH] Found keylogger code in: /tmp/keylog.py
    [HIGH] Suspicious process keylog.exe has network connection to 192.168.1.100:8080

[REPORT] Saved: reports/report.json

## Risk Levels

| Level | Score | Description |
|-------|-------|-------------|
| SAFE | 0-9 | No suspicious activity found |
| LOW | 10-29 | Minor findings |
| MEDIUM | 30-49 | Moderate suspicious activity |
| HIGH | 50-69 | Significant suspicious activity |
| CRITICAL | 70+ | Severe threats detected |

## Implemented

- Scheduled scanning (`--interval`)
- Whitelist for known processes (`-w/--whitelist`, plus a built-in baseline)

## Future Improvements

- Wazuh SIEM integration
- Real-time notifications
- Web interface

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea