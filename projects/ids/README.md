# Intrusion Detection System (IDS)

A network-based intrusion detection system that uses tcpdump to capture and analyze traffic for suspicious activity.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates:

- Real-time traffic analysis
- Attack detection (port scan, SYN flood, ICMP flood, brute force)
- Alert generation
- MITRE ATT&CK mapping

## Technologies

- Python 3.14+
- tcpdump
- Subprocess
- Regex
- JSON

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/ids

pip install -r requirements.txt

## Usage

sudo python3 ids_file.py -i <INTERFACE> -t <DURATION>

### Options

| Option | Description |
|--------|-------------|
| -i, --interface | Network interface (default: eth0) |
| -t, --time | Capture duration in seconds (default: 30) |
| -f, --filter | BPF filter (optional) |

### Examples

Capture on eth0 for 30 seconds:
sudo python3 ids_file.py -i eth0 -t 30

Capture on wlan0 for 60 seconds:
sudo python3 ids_file.py -i wlan0 -t 60

## Detection Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| IDS-001 | Port Scan Detection | HIGH | 10+ SYN packets to different ports in 10s |
| IDS-002 | Brute Force Detection | HIGH | 5+ auth attempts in 30s |
| IDS-003 | ICMP Flood Detection | MEDIUM | 10+ ICMP requests in 5s |
| IDS-004 | SYN Flood Detection | HIGH | 20+ SYN packets in 5s |

## Example Output

[IDS] Monitoring eth0 for 30s...

[ALERT] IDS-001 - Port Scan Detection
   Severity: HIGH
   Source: 192.168.1.100
   Destination: 10.0.0.1
   Count: 15

[STATS] Packets: 150, Alerts: 2

[STATS] Captured 150 packets
[STATS] Alerts: 2

[REPORT] Saved: reports/report.json

## Testing

Generate traffic for testing:

Port scan:
nmap -p 1-50 8.8.8.8

Ping flood:
ping -i 0.01 -c 100 8.8.8.8

## Report Example (JSON)

{
  "timestamp": "2026-08-04T14:53:00.123456",
  "packets_captured": 150,
  "alerts_triggered": 2,
  "alerts": [
    {
      "rule_id": "IDS-001",
      "rule_name": "Port Scan Detection",
      "severity": "HIGH",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.1",
      "ports": [20, 21, 22],
      "count": 3,
      "timestamp": "2026-08-04T14:53:00.123456"
    }
  ]
}

## Future Improvements

- Wazuh SIEM integration
- Web interface (Flask)
- Real-time notifications (Slack/Discord)
- ARP spoofing detection
- DNS amplification detection
- Elasticsearch export

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea