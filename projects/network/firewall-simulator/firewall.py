#!/usr/bin/env python3
"""
Firewall Simulator - Robert Mircea
Homelab Project

Simulates firewall rule-based packet filtering with allow/deny rules, priorities, and logging.
"""

import json
import os
import random
import time
import argparse
from datetime import datetime
from collections import defaultdict


class Firewall:
    """Firewall simulator with rule-based packet filtering."""

    def __init__(self, rules_file=None):
        if rules_file is None:
            rules_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules', 'rules.json')
        self.rules_file = rules_file
        self.rules = self._load_rules(rules_file)
        self.logs = []
        self.stats = {
            'allowed': 0,
            'denied': 0,
            'dropped': 0,
            'total': 0
        }
        self.rules_hit = defaultdict(int)
        # Advanced statistics accumulators.
        self.proto_stats = defaultdict(int)
        self.src_talkers = defaultdict(int)
        self.dst_talkers = defaultdict(int)

    def _load_rules(self, rules_file):
        """Load rules from JSON file or create defaults."""
        if os.path.exists(rules_file):
            with open(rules_file, 'r') as f:
                return json.load(f)

        # Default rules
        default_rules = [
            {'id': 1, 'name': 'Allow HTTP', 'action': 'allow', 'protocol': 'tcp',
             'src_ip': '*', 'dst_ip': '*', 'src_port': '*', 'dst_port': '80', 'priority': 10},
            {'id': 2, 'name': 'Allow HTTPS', 'action': 'allow', 'protocol': 'tcp',
             'src_ip': '*', 'dst_ip': '*', 'src_port': '*', 'dst_port': '443', 'priority': 10},
            {'id': 3, 'name': 'Allow SSH', 'action': 'allow', 'protocol': 'tcp',
             'src_ip': '192.168.1.0/24', 'dst_ip': '*', 'src_port': '*', 'dst_port': '22', 'priority': 10},
            {'id': 4, 'name': 'Block all', 'action': 'deny', 'protocol': '*',
             'src_ip': '*', 'dst_ip': '*', 'src_port': '*', 'dst_port': '*', 'priority': 100}
        ]

        os.makedirs(os.path.dirname(rules_file), exist_ok=True)
        with open(rules_file, 'w') as f:
            json.dump(default_rules, f, indent=2)

        return default_rules

    def _save_rules(self):
        """Save current rules to JSON file."""
        with open(self.rules_file, 'w') as f:
            json.dump(self.rules, f, indent=2)

    def add_rule(self, rule):
        """Add a new rule to the firewall."""
        rule['id'] = max([r['id'] for r in self.rules]) + 1 if self.rules else 1
        self.rules.append(rule)
        self._save_rules()
        print(f"[RULE] Added: {rule['name']} (ID: {rule['id']})")

    def _match_rule(self, rule, packet):
        """Check if a packet matches a specific rule."""
        if rule['protocol'] != '*' and rule['protocol'] != packet.get('protocol'):
            return False

        if rule['src_ip'] != '*':
            if not self._ip_in_range(packet.get('src_ip'), rule['src_ip']):
                return False

        if rule['dst_ip'] != '*':
            if not self._ip_in_range(packet.get('dst_ip'), rule['dst_ip']):
                return False

        if rule['src_port'] != '*':
            if str(packet.get('src_port')) != str(rule['src_port']):
                return False

        if rule['dst_port'] != '*':
            if str(packet.get('dst_port')) != str(rule['dst_port']):
                return False

        # Time-based rules: optional "time_start"/"time_end" as "HH:MM".
        if rule.get('time_start') and rule.get('time_end'):
            if not self._time_in_window(rule['time_start'], rule['time_end']):
                return False

        return True

    def _time_in_window(self, start, end):
        """Return True if the current local time falls within [start, end]."""
        now = datetime.now().strftime('%H:%M')
        if start <= end:
            return start <= now <= end
        # Window wraps past midnight (e.g. 22:00 -> 06:00).
        return now >= start or now <= end

    def _ip_in_range(self, ip, cidr):
        """Check if IP is within CIDR range."""
        if ip is None:
            return False

        if '/' in cidr:
            network, mask = cidr.split('/')
            mask = int(mask)
            ip_parts = ip.split('.')
            net_parts = network.split('.')

            if mask == 24:
                return ip_parts[:3] == net_parts[:3]
            elif mask == 16:
                return ip_parts[:2] == net_parts[:2]
            elif mask == 8:
                return ip_parts[:1] == net_parts[:1]
            return True
        else:
            return ip == cidr

    def _check_rule(self, packet):
        """Find the matching rule for a packet."""
        sorted_rules = sorted(self.rules, key=lambda x: x['priority'])

        for rule in sorted_rules:
            if self._match_rule(rule, packet):
                self.rules_hit[rule['id']] += 1
                return rule['action'], rule['id']

        return 'deny', None

    def simulate_packet(self, packet):
        """Simulate a single packet through the firewall."""
        self.stats['total'] += 1

        action, rule_id = self._check_rule(packet)

        # Advanced statistics.
        self.proto_stats[packet.get('protocol', 'unknown')] += 1
        if packet.get('src_ip'):
            self.src_talkers[packet['src_ip']] += 1
        if packet.get('dst_ip'):
            self.dst_talkers[packet['dst_ip']] += 1

        if action == 'allow':
            self.stats['allowed'] += 1
            status = 'ALLOW'
        elif action == 'deny':
            self.stats['denied'] += 1
            status = 'DENY'
        else:
            self.stats['dropped'] += 1
            status = 'DROP'

        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'packet': packet,
            'action': status,
            'rule_id': rule_id
        }
        self.logs.append(log_entry)

        print(f"[{status}] {packet.get('src_ip', '*')}:{packet.get('src_port', '*')} -> "
              f"{packet.get('dst_ip', '*')}:{packet.get('dst_port', '*')} "
              f"({packet.get('protocol', 'ANY')}) Rule: {rule_id}")

        return status

    def simulate_traffic(self, count=10):
        """Generate and simulate random network traffic."""
        protocols = ['tcp', 'udp', 'icmp']
        ips = [
            '192.168.1.1', '192.168.1.10', '192.168.1.100',
            '10.0.0.1', '10.0.0.50', '10.0.0.200',
            '172.16.0.1', '172.16.0.100',
            '8.8.8.8', '1.1.1.1'
        ]
        ports = [22, 80, 443, 25, 53, 8080, 3306, 5432]

        print(f"\n[TRAFFIC] Simulating {count} packets...")
        print("-" * 50)

        for _ in range(count):
            packet = {
                'protocol': random.choice(protocols),
                'src_ip': random.choice(ips),
                'dst_ip': random.choice(ips),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice(ports)
            }

            # Random suspicious traffic
            if random.random() < 0.2:
                packet['dst_port'] = random.randint(1, 1024)

            self.simulate_packet(packet)
            time.sleep(0.05)

    def export_rules(self, path):
        """Export the current rule set to a JSON file."""
        with open(path, 'w') as f:
            json.dump(self.rules, f, indent=2)
        print(f"[RULES] Exported {len(self.rules)} rules to {path}")

    def import_rules(self, path):
        """Import (replace) the rule set from a JSON file."""
        if not os.path.exists(path):
            print(f"[ERROR] File not found: {path}")
            return
        with open(path, 'r') as f:
            imported = json.load(f)
        self.rules = imported
        self._save_rules()
        print(f"[RULES] Imported {len(imported)} rules from {path}")

    def import_pcap(self, path):
        """Replay packets from a PCAP file through the firewall (needs scapy)."""
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP
        except ImportError:
            print("[ERROR] scapy is required for PCAP import (pip install scapy)")
            return

        if not os.path.exists(path):
            print(f"[ERROR] PCAP not found: {path}")
            return

        packets = rdpcap(path)
        print(f"\n[PCAP] Replaying {len(packets)} packets from {path}...")
        print("-" * 50)

        for pkt in packets:
            if IP not in pkt:
                continue
            proto, sport, dport = 'ip', '*', '*'
            if TCP in pkt:
                proto, sport, dport = 'tcp', pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto, sport, dport = 'udp', pkt[UDP].sport, pkt[UDP].dport
            elif ICMP in pkt:
                proto = 'icmp'

            self.simulate_packet({
                'protocol': proto,
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'src_port': sport,
                'dst_port': dport,
            })

    def generate_report(self):
        """Generate a detailed firewall report."""
        _rep = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
        os.makedirs(_rep, exist_ok=True)

        top_src = sorted(self.src_talkers.items(), key=lambda x: x[1], reverse=True)[:5]
        top_dst = sorted(self.dst_talkers.items(), key=lambda x: x[1], reverse=True)[:5]

        report = {
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'protocol_breakdown': dict(self.proto_stats),
            'top_sources': dict(top_src),
            'top_destinations': dict(top_dst),
            'rules_hit': dict(self.rules_hit),
            'total_logs': len(self.logs),
            'recent_logs': self.logs[-10:]
        }

        with open(os.path.join(_rep, 'report.json'), 'w') as f:
            json.dump(report, f, indent=2)

        print("\n" + "=" * 50)
        print("[REPORT] Firewall Report")
        print("=" * 50)
        print(f"  Total packets: {self.stats['total']}")

        if self.stats['total'] > 0:
            print(f"  ALLOWED: {self.stats['allowed']} ({self.stats['allowed']/self.stats['total']*100:.1f}%)")
            print(f"  DENIED:  {self.stats['denied']} ({self.stats['denied']/self.stats['total']*100:.1f}%)")
            print(f"  DROPPED: {self.stats['dropped']} ({self.stats['dropped']/self.stats['total']*100:.1f}%)")

        if self.rules_hit:
            print("\n  Top rules hit:")
            sorted_rules = sorted(self.rules_hit.items(), key=lambda x: x[1], reverse=True)
            for rule_id, count in sorted_rules[:5]:
                rule = next((r for r in self.rules if r['id'] == rule_id), None)
                if rule:
                    print(f"    Rule {rule_id}: {rule['name']} - {count} hits")

        if self.proto_stats:
            print("\n  Protocol breakdown:")
            for proto, count in sorted(self.proto_stats.items(), key=lambda x: x[1], reverse=True):
                print(f"    {proto}: {count}")

        if top_src:
            print("\n  Top source talkers:")
            for ip, count in top_src:
                print(f"    {ip}: {count} packets")

        print(f"\n[REPORT] Saved: reports/report.json")


def main():
    parser = argparse.ArgumentParser(description="Firewall Simulator")
    parser.add_argument("-a", "--add", help="Add rule: name:action:protocol:src_ip:dst_ip:src_port:dst_port:priority")
    parser.add_argument("-s", "--simulate", type=int, default=10, help="Number of packets to simulate")
    parser.add_argument("-l", "--list", action="store_true", help="List all rules")
    parser.add_argument("-R", "--report", action="store_true", help="Generate report")
    parser.add_argument("--export", metavar="FILE", help="Export rules to a JSON file")
    parser.add_argument("--import", dest="import_file", metavar="FILE",
                        help="Import (replace) rules from a JSON file")
    parser.add_argument("--pcap", metavar="FILE", help="Replay packets from a PCAP file")

    args = parser.parse_args()

    firewall = Firewall()

    if args.export:
        firewall.export_rules(args.export)
    elif args.import_file:
        firewall.import_rules(args.import_file)
    elif args.pcap:
        firewall.import_pcap(args.pcap)
        firewall.generate_report()
    elif args.add:
        parts = args.add.split(':')
        if len(parts) >= 8:
            rule = {
                'name': parts[0],
                'action': parts[1],
                'protocol': parts[2],
                'src_ip': parts[3],
                'dst_ip': parts[4],
                'src_port': parts[5],
                'dst_port': parts[6],
                'priority': int(parts[7])
            }
            firewall.add_rule(rule)
        else:
            print("[ERROR] Format: name:action:protocol:src_ip:dst_ip:src_port:dst_port:priority")

    elif args.list:
        print("\n[RULES] Current rules:")
        print("-" * 60)
        for rule in firewall.rules:
            print(f"  ID: {rule['id']} | {rule['name']} | {rule['action']} | "
                  f"{rule['protocol']} | {rule['src_ip']} -> {rule['dst_ip']} | "
                  f"Priority: {rule['priority']}")

    elif args.report:
        firewall.generate_report()

    else:
        firewall.simulate_traffic(args.simulate)
        firewall.generate_report()


if __name__ == "__main__":
    main()