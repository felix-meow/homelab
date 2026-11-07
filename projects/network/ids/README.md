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
cd homelab/projects/network/ids

pip install -r requirements.txt

## Usage

python3 ids_file.py -i <INTERFACE> -t <DURATION> [-f "<BPF filter>"]

The IDS does not need to run as root. Give tcpdump capture capabilities once,
restricted to a dedicated group (the same model Wireshark uses for dumpcap):

```bash
sudo groupadd -f pcap
sudo usermod -aG pcap "$USER"
sudo dpkg-statoverride --update --add root pcap 750 /usr/bin/tcpdump
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump
# then open a new login shell so the group membership applies
```

`dpkg-statoverride` keeps the owner/mode across tcpdump package upgrades; an
upgrade does reset the capabilities, so re-run the `setcap` line after one.
Without this setup, use `--sudo`.

### Options

| Option | Description |
|--------|-------------|
| -i, --interface | Network interface (default: eth0); must exist in /sys/class/net |
| -t, --time | Capture duration in seconds (default: 30) |
| -f, --filter | BPF filter expression (optional), e.g. `"tcp or icmp"` |
| --sudo | Run tcpdump through sudo (only if your user lacks capture capabilities) |

Set `N8N_WEBHOOK_URL` to also forward each alert as JSON to an n8n webhook.

### Examples

Capture on eth0 for 30 seconds:
python3 ids_file.py -i eth0 -t 30

Capture only TCP/ICMP on wlan0 for 60 seconds:
python3 ids_file.py -i wlan0 -t 60 -f "tcp or icmp"

### Security notes

- tcpdump is launched from an argv list, never through a shell, so the interface
  and filter values cannot inject shell commands.
- The interface must be an existing interface name; the BPF filter is passed
  after `--`, so it can only be a filter expression, never extra tcpdump options
  (such as `-z`, which runs a command).

## Detection Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| IDS-001 | Port Scan Detection | HIGH | 10+ SYN packets to different ports in 10s |
| IDS-002 | Brute Force Detection | HIGH | 5+ auth attempts in 30s |
| IDS-003 | ICMP Flood Detection | MEDIUM | 10+ ICMP requests in 5s |
| IDS-004 | SYN Flood Detection | HIGH | 20+ SYN packets in 5s |
| IDS-005 | ARP Spoofing Detection | HIGH | An IP's advertised MAC address changes |
| IDS-006 | DNS Amplification Detection | MEDIUM | 10+ large (200B+) DNS responses to one target in 5s |

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

Only test against machines you own. The simplest target is your own host:
run the IDS on the loopback interface and generate traffic to 127.0.0.1 from a
second terminal.

python3 ids_file.py -i lo -t 60

Port scan (IDS-001):
nmap -p 1-50 127.0.0.1

Ping flood (IDS-003):
ping -i 0.2 -c 30 127.0.0.1

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

## Implemented

- ARP spoofing detection (IDS-005)
- DNS amplification detection (IDS-006)

## Future Improvements

- Wazuh SIEM integration
- Web interface (Flask)
- Real-time notifications (Slack/Discord)
- Elasticsearch export

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea