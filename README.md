# Cybersecurity Homelab

A complete cybersecurity portfolio built from scratch. Includes 10 custom Python security tools, a unified web dashboard, and integration with various security technologies.

---

## About

This homelab represents the foundation of my cybersecurity portfolio. Each tool is built from the ground up to demonstrate a deep understanding of offensive and defensive security concepts.

Goals:
- Demonstrate practical cybersecurity skills
- Understand protocols and vulnerabilities at a deep level
- Build a solid portfolio for a career in security
- Automate and integrate within a homelab environment

---

## Architecture

| Component | Role |
|-----------|------|
| Laptop (Windows 11 + WSL) | Host / Development environment |
| Docker | Containerization (n8n, Ollama, PostgreSQL) |
| Python 3.14+ | Primary language for all tools |
| Phone (Kali NetHunter) | Mobile security / testing |

---

## Structure
```
homelab/
├── README.md
├── requirements.txt
├── projects/
│   ├── port-scanner/
│   ├── packet-sniffer/
│   ├── file-integrity-monitor/
│   ├── web-vuln-scanner/
│   ├── ids/
│   ├── password-cracker/
│   ├── phishing-detector/
│   ├── firewall-simulator/
│   ├── encrypted-chat/
│   └── keylogger-detector/
└── docs/
    └── incident-response/
```
---

## Projects

1. Port Scanner
TCP scanner for identifying open services.

2. Packet Sniffer
Network packet capture and analysis.

3. File Integrity Monitor
File integrity monitoring using SHA256 hashes.

4. Web Vulnerability Scanner
Detection of XSS, SQLi, LFI, and Open Redirect.

5. Intrusion Detection System
Detection of port scans, SYN floods, and brute force attempts.

6. Password Cracker
Hash cracking using dictionary, brute-force, and hybrid attacks.

7. Phishing Detector
Email analysis for phishing attempts.

8. Firewall Simulator
Firewall rule simulation and packet filtering.

9. Encrypted Chat
End-to-end encrypted chat (AES-128).

10. Keylogger Detector
Detection of keyloggers and spyware.

---

## Installation

Clone the repository:
git clone https://github.com/felix-meow/homelab.git
cd homelab

Create and activate the virtual environment:
python3 -m venv venv
source venv/bin/activate

Install general dependencies:
pip install -r requirements.txt

For each project, navigate to its folder and install specific dependencies:
cd projects/port-scanner
pip install -r requirements.txt

---

## Quick Test

Port Scanner:
python3 projects/port-scanner/port_scanner.py -H scanme.nmap.org

Web Vulnerability Scanner:
python3 projects/web-vuln-scanner/scanner.py -u http://testaspnet.vulnweb.com

Phishing Detector:
python3 projects/phishing-detector/detector.py -s "Test" -b "http://fake.com"

---

## Technologies

| Category | Technologies |
|----------|--------------|
| Language | Python 3.14+ |
| Networking | Scapy, socket, requests |
| Security | cryptography, hashlib |
| System | psutil, os, subprocess |
| Automation | n8n, Docker |
| Analysis | BeautifulSoup4, re, json |

---

## Roadmap

- Wazuh SIEM integration
- Web interface for each tool
- Full n8n automation
- Portable Cyberdeck
- Eye Scanner

---

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea
Email: mircearbt@gmail.com

---

*Project built as part of a cybersecurity portfolio.*
