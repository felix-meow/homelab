# Firewall Simulator

A packet filtering firewall simulator with rule-based allow/deny decisions, priority processing, and traffic logging.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates:

- Firewall rule processing
- Packet filtering (IP, port, protocol)
- Priority-based rule evaluation
- Traffic simulation and logging

## Technologies

- Python 3.14+
- JSON (rules and reports)
- Random (traffic simulation)

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/firewall-simulator

pip install -r requirements.txt

## Usage

python3 firewall.py [OPTIONS]

### Options

| Option | Description |
|--------|-------------|
| -s, --simulate | Number of packets to simulate (default: 10) |
| -l, --list | List all rules |
| -a, --add | Add a new rule |
| -R, --report | Generate report |

### Adding a Rule

Format: name:action:protocol:src_ip:dst_ip:src_port:dst_port:priority

python3 firewall.py -a "Block SSH:deny:tcp:*:*:*:22:5"

### Examples

Simulate traffic:
python3 firewall.py -s 20

List rules:
python3 firewall.py -l

Add rule:
python3 firewall.py -a "Block SSH:deny:tcp:*:*:*:22:5"

Generate report:
python3 firewall.py -R

## Default Rules

| ID | Name | Action | Protocol | Source | Destination | Port | Priority |
|----|------|--------|----------|--------|-------------|------|----------|
| 1 | Allow HTTP | allow | tcp | * | * | 80 | 10 |
| 2 | Allow HTTPS | allow | tcp | * | * | 443 | 10 |
| 3 | Allow SSH | allow | tcp | 192.168.1.0/24 | * | 22 | 10 |
| 4 | Block all | deny | * | * | * | * | 100 |

## Example Output

[TRAFFIC] Simulating 20 packets...
--------------------------------------------------
[ALLOW] 192.168.1.1:54321 -> 8.8.8.8:443 (tcp) Rule: 2
[DENY] 10.0.0.50:12345 -> 192.168.1.1:22 (tcp) Rule: 4

==================================================
[REPORT] Firewall Report
==================================================
  Total packets: 20
  ALLOWED: 14 (70.0%)
  DENIED: 6 (30.0%)
  DROPPED: 0 (0.0%)

  Top rules hit:
    Rule 2: Allow HTTPS - 8 hits
    Rule 4: Block all - 6 hits

[REPORT] Saved: reports/report.json

## Future Improvements

- Time-based rules
- Web interface
- Import/export rules
- Advanced statistics
- PCAP traffic import

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea