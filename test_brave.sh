#!/bin/bash
echo "🔍 Brave Bug Bounty Test Suite"
echo "================================"
echo ""

# 1. Port Scanner
echo "[1] Port Scanner - search.brave.com"
cd ~/homelab/projects/port-scanner
python3 port_scanner.py -H search.brave.com -p 80,443,8080,8443

echo ""
echo "[2] Web Vuln Scanner - search.brave.com"
cd ~/homelab/projects/web-vuln-scanner
python3 scanner.py -u https://search.brave.com -d 1

echo ""
echo "[3] Web Vuln Scanner - account.brave.com"
python3 scanner.py -u https://account.brave.com -d 1

echo ""
echo "[4] Packet Sniffer (HTTPS traffic)"
cd ~/homelab/projects/packet-sniffer
echo "Rulează în alt terminal: curl -4 https://search.brave.com"
echo "sudo /home/roby/homelab/venv/bin/python3 sniffer.py -i eth0 -f 'tcp port 443' -c 20"

echo ""
echo "✅ Test suită completă!"
