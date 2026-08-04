# Packet Sniffer

A modular network packet sniffer built with Scapy for real-time traffic analysis, anomaly detection, and SIEM integration.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It provides:

- Live packet capture and analysis
- BPF filtering support
- HTTP header extraction
- IP/TCP/UDP/ICMP parsing
- JSON report generation

## Technologies

- Python 3.14+
- Scapy 2.7.0
- libpcap
- BPF (Berkeley Packet Filter)

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/packet-sniffer

pip install -r requirements.txt

sudo apt update
sudo apt install libpcap-dev -y

## Usage

sudo python3 sniffer.py [OPTIONS]

### Options

| Option | Description |
|--------|-------------|
| -i, --interface | Network interface (e.g., eth0, wlan0) |
| -f, --filter | BPF filter (e.g., "tcp port 80") |
| -c, --count | Number of packets to capture |
| -h, --help | Show help message |

### Examples

ICMP capture (ping):
sudo python3 sniffer.py -i eth0 -f "icmp" -c 5

HTTP capture:
sudo python3 sniffer.py -i eth0 -f "tcp port 80" -c 5

HTTPS capture:
sudo python3 sniffer.py -i eth0 -f "tcp port 443" -c 10

DNS capture:
sudo python3 sniffer.py -i lo -f "udp port 53" -c 5

General capture:
sudo python3 sniffer.py -i eth0 -c 20

## Example Output

[PACKET] #1 | 2026-08-04T12:19:23.598158
    Summary: Ether / IP / TCP 172.17.156.200:46634 > 104.20.23.154:https S
    IP: 172.17.156.200 -> 104.20.23.154
    Protocol: 6
    Port: 46634 -> 443
    Length: 74 bytes

## Features

| Feature | Status |
|---------|--------|
| Live capture | Yes |
| BPF filters | Yes |
| IP/TCP/UDP/ICMP analysis | Yes |
| HTTP extraction | Yes |
| JSON reports | Yes |

## Tested On

- WSL 2 (Ubuntu 22.04 / 24.04)
- Interfaces: eth0, lo
- Protocols: ICMP, DNS, HTTP, HTTPS

## Debugging

libpcap not found:
sudo apt install libpcap-dev tcpdump -y

No module named scapy:
pip install scapy

Permission denied:
sudo python3 sniffer.py [options]

## Future Improvements

- PCAP export (Wireshark compatible)
- Banner grabbing
- ARP spoofing detection
- Web interface (Flask)
- Wazuh SIEM integration
- DDoS detection (SYN flood)
- Elasticsearch export
- OS fingerprinting

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea