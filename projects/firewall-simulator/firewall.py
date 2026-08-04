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

    def __init__(self, rules_file='rules/rules.json'):
        self.rules = self._load_rules(rules_file)
        self.logs = []
        self.stats = {
            'allowed': 0,
            'denied': 0,
            'dropped': 0,
            'total': 0
        }
        self.rules_hit = defaultdict(int)

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

        os.makedirs('rules', exist_ok=True)
        with open(rules_file, 'w') as f:
            json.dump(default_rules, f, indent=2)

        return default_rules

    def _save_rules(self):
        """Save current rules to JSON file."""
        with open('rules/rules.json', 'w') as f:
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

        return True

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

    def generate_report(self):
        """Generate a detailed firewall report."""
        os.makedirs('reports', exist_ok=True)

        report = {
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'rules_hit': dict(self.rules_hit),
            'total_logs': len(self.logs),
            'recent_logs': self.logs[-10:]
        }

        with open('reports/report.json', 'w') as f:
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

        print(f"\n[REPORT] Saved: reports/report.json")


def main():
    parser = argparse.ArgumentParser(description="Firewall Simulator")
    parser.add_argument("-a", "--add", help="Add rule: name:action:protocol:src_ip:dst_ip:src_port:dst_port:priority")
    parser.add_argument("-s", "--simulate", type=int, default=10, help="Number of packets to simulate")
    parser.add_argument("-l", "--list", action="store_true", help="List all rules")
    parser.add_argument("-R", "--report", action="store_true", help="Generate report")

    args = parser.parse_args()

    firewall = Firewall()

    if args.add:
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