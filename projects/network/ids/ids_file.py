#!/usr/bin/env python3
"""
Intrusion Detection System - Robert Mircea
Homelab Project

Network-based IDS that detects port scans, SYN floods, ICMP floods, and brute force attempts using tcpdump.
"""

import subprocess
import time
import json
import os
import re
import argparse
from datetime import datetime
from collections import defaultdict

# Anchor output to the tool's own directory so reports/alerts land here no
# matter what the current working directory is (the red/blue pair commands run
# this tool from a sibling folder, e.g. ../ids/ids_file.py).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class IDS:
    """Intrusion Detection System using tcpdump for packet capture."""

    def __init__(self, interface="eth0"):
        self.interface = interface
        self.alerts = []
        self.packet_count = 0
        self.running = True

        # Detection counters
        self.syn_counter = defaultdict(list)
        self.icmp_counter = defaultdict(list)
        self.auth_failures = defaultdict(list)
        self.dns_responses = defaultdict(list)
        self.arp_table = {}

        # Rules configuration
        self.rules = {
            "port_scan": {"threshold": 10, "time_window": 10, "severity": "HIGH"},
            "syn_flood": {"threshold": 20, "time_window": 5, "severity": "HIGH"},
            "icmp_flood": {"threshold": 10, "time_window": 5, "severity": "MEDIUM"},
            "brute_force": {"threshold": 5, "time_window": 30, "severity": "HIGH"},
            "dns_amplification": {"threshold": 10, "time_window": 5, "severity": "MEDIUM"},
        }

    def capture_packets(self, duration=30):
        """
        Capture packets using tcpdump and analyze them in real-time.
        """
        cmd = f"timeout {duration} sudo tcpdump -i {self.interface} -n 2>/dev/null"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True)

        print(f"[IDS] Monitoring {self.interface} for {duration}s...")

        for line in process.stdout:
            self.packet_count += 1
            self.analyze_packet(line.strip())

            if self.packet_count % 50 == 0:
                print(f"[STATS] Packets: {self.packet_count}, Alerts: {len(self.alerts)}")

        process.wait()
        print(f"\n[STATS] Captured {self.packet_count} packets")
        print(f"[STATS] Alerts: {len(self.alerts)}")
        self.generate_report()

    def analyze_packet(self, line):
        """
        Parse and analyze a single packet line from tcpdump.
        """
        # SYN packet detection (port scan)
        if "[S]" in line and "Flags" in line and not "[S.]" in line:
            match = re.search(r'IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):', line)
            if match:
                src_ip = match.group(1)
                src_port = int(match.group(2))
                dst_ip = match.group(3)
                dst_port = int(match.group(4))
                self.detect_port_scan(src_ip, dst_ip, dst_port)
                self.detect_syn_flood(src_ip)

        # ICMP detection
        if "ICMP echo request" in line:
            match = re.search(r'IP (\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+):', line)
            if match:
                src_ip = match.group(1)
                dst_ip = match.group(2)
                self.detect_icmp_flood(src_ip, dst_ip)

        # SSH/FTP brute force detection (port 22, 21)
        if "Flags" in line and ("22" in line or "21" in line):
            match = re.search(r'IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):', line)
            if match:
                src_ip = match.group(1)
                dst_ip = match.group(3)
                dst_port = int(match.group(4))
                if dst_port in [22, 21]:
                    self.detect_brute_force(src_ip, dst_ip, dst_port)

        # ARP spoofing detection.
        # tcpdump format: "ARP, Reply 192.168.1.1 is-at aa:bb:cc:dd:ee:ff, ..."
        if "ARP, Reply" in line:
            match = re.search(r'Reply (\d+\.\d+\.\d+\.\d+) is-at ([0-9a-fA-F:]{17})', line)
            if match:
                self.detect_arp_spoof(match.group(1), match.group(2))

        # DNS amplification detection.
        # A response from source port 53 with a large payload.
        if ".53 > " in line:
            match = re.search(
                r'IP (\d+\.\d+\.\d+\.\d+)\.53 > (\d+\.\d+\.\d+\.\d+)\.\d+:.*\((\d+)\)',
                line,
            )
            if match:
                self.detect_dns_amplification(
                    match.group(1), match.group(2), int(match.group(3))
                )

    def detect_port_scan(self, src_ip, dst_ip, dst_port):
        """Detect port scanning behavior."""
        key = f"{src_ip}:{dst_ip}"
        self.syn_counter[key].append({'port': dst_port, 'time': time.time()})

        # Keep only recent entries
        now = time.time()
        recent = [p for p in self.syn_counter[key] if now - p['time'] < self.rules['port_scan']['time_window']]
        ports = set([p['port'] for p in recent])

        if len(ports) >= self.rules['port_scan']['threshold']:
            alert = {
                'rule_id': 'IDS-001',
                'rule_name': 'Port Scan Detection',
                'severity': self.rules['port_scan']['severity'],
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'ports': list(ports),
                'count': len(ports)
            }
            self.trigger_alert(alert)
            self.syn_counter[key] = []

    def detect_syn_flood(self, src_ip):
        """Detect SYN flood attacks."""
        self.syn_counter[src_ip].append(time.time())

        now = time.time()
        recent = [t for t in self.syn_counter[src_ip] if now - t < self.rules['syn_flood']['time_window']]

        if len(recent) >= self.rules['syn_flood']['threshold']:
            alert = {
                'rule_id': 'IDS-004',
                'rule_name': 'SYN Flood Detection',
                'severity': self.rules['syn_flood']['severity'],
                'src_ip': src_ip,
                'count': len(recent)
            }
            self.trigger_alert(alert)
            self.syn_counter[src_ip] = []

    def detect_icmp_flood(self, src_ip, dst_ip):
        """Detect ICMP flood attacks."""
        key = f"icmp:{src_ip}"
        self.icmp_counter[key].append(time.time())

        now = time.time()
        recent = [t for t in self.icmp_counter[key] if now - t < self.rules['icmp_flood']['time_window']]

        if len(recent) >= self.rules['icmp_flood']['threshold']:
            alert = {
                'rule_id': 'IDS-003',
                'rule_name': 'ICMP Flood Detection',
                'severity': self.rules['icmp_flood']['severity'],
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'count': len(recent)
            }
            self.trigger_alert(alert)
            self.icmp_counter[key] = []

    def detect_brute_force(self, src_ip, dst_ip, dst_port):
        """Detect brute force attempts on SSH/FTP."""
        key = f"{src_ip}:{dst_ip}:{dst_port}"
        self.auth_failures[key].append(time.time())

        now = time.time()
        recent = [t for t in self.auth_failures[key] if now - t < self.rules['brute_force']['time_window']]

        if len(recent) >= self.rules['brute_force']['threshold']:
            alert = {
                'rule_id': 'IDS-002',
                'rule_name': 'Brute Force Detection',
                'severity': self.rules['brute_force']['severity'],
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'count': len(recent)
            }
            self.trigger_alert(alert)
            self.auth_failures[key] = []

    def detect_arp_spoof(self, ip, mac):
        """Detect ARP cache poisoning: an IP whose advertised MAC changes."""
        known = self.arp_table.get(ip)
        if known and known != mac:
            self.trigger_alert({
                'rule_id': 'IDS-005',
                'rule_name': 'ARP Spoofing Detection',
                'severity': 'HIGH',
                'src_ip': ip,
                'old_mac': known,
                'new_mac': mac,
                'count': 1,
            })
        self.arp_table[ip] = mac

    def detect_dns_amplification(self, src_ip, dst_ip, size):
        """Detect DNS amplification: many large responses toward one target."""
        rule = self.rules['dns_amplification']
        # Only large responses are relevant to amplification abuse.
        if size < 200:
            return

        key = f"{src_ip}:{dst_ip}"
        self.dns_responses[key].append(time.time())

        now = time.time()
        recent = [t for t in self.dns_responses[key] if now - t < rule['time_window']]
        self.dns_responses[key] = recent

        if len(recent) >= rule['threshold']:
            self.trigger_alert({
                'rule_id': 'IDS-006',
                'rule_name': 'DNS Amplification Detection',
                'severity': rule['severity'],
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'response_size': size,
                'count': len(recent),
            })
            self.dns_responses[key] = []

    def trigger_alert(self, alert):
        """Trigger and log an alert."""
        alert['timestamp'] = datetime.now().isoformat()
        self.alerts.append(alert)

        # Print to console with color
        colors = {'HIGH': '\033[91m', 'MEDIUM': '\033[93m', 'LOW': '\033[94m'}
        color = colors.get(alert['severity'], '\033[0m')
        reset = '\033[0m'

        print(f"\n{color}[ALERT] {alert['rule_id']} - {alert['rule_name']}")
        print(f"   Severity: {alert['severity']}")
        print(f"   Source: {alert.get('src_ip', 'N/A')}")
        print(f"   Destination: {alert.get('dst_ip', 'N/A')}")
        print(f"   Count: {alert.get('count', 'N/A')}{reset}")

        # Save to log file
        alerts_dir = os.path.join(BASE_DIR, 'alerts')
        os.makedirs(alerts_dir, exist_ok=True)
        with open(os.path.join(alerts_dir, 'alerts.log'), 'a') as f:
            f.write(json.dumps(alert) + '\n')

        # Optional: forward the alert to an n8n webhook (non-blocking; a down
        # webhook must never affect detection). Set env N8N_WEBHOOK_URL to enable.
        _wh = os.environ.get("N8N_WEBHOOK_URL")
        if _wh:
            try:
                import urllib.request
                _req = urllib.request.Request(
                    _wh, data=json.dumps(alert).encode("utf-8"),
                    headers={"Content-Type": "application/json"}, method="POST")
                urllib.request.urlopen(_req, timeout=3).close()
            except Exception:
                pass

    def generate_report(self):
        """Generate a JSON report of all alerts."""
        reports_dir = os.path.join(BASE_DIR, 'reports')
        os.makedirs(reports_dir, exist_ok=True)

        report = {
            'timestamp': datetime.now().isoformat(),
            'packets_captured': self.packet_count,
            'alerts_triggered': len(self.alerts),
            'alerts': self.alerts
        }

        report_path = os.path.join(reports_dir, 'report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[REPORT] Saved: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="Intrusion Detection System")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface")
    parser.add_argument("-t", "--time", type=int, default=30, help="Capture duration in seconds")
    parser.add_argument("-f", "--filter", help="BPF filter (optional)")

    args = parser.parse_args()

    ids = IDS(args.interface)
    ids.capture_packets(args.time)


if __name__ == "__main__":
    main()