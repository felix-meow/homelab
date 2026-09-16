#!/usr/bin/env python3
"""
DDoS / Attack-Traffic Simulator - Robert Mircea
Homelab Project - OFFENSIVE (red-team pair for ids / firewall-simulator)

Generates attack-pattern traffic (SYN flood, port scan, ICMP flood, DNS query
burst) so the IDS and firewall-simulator can be validated end to end.

LAB-SAFE BY DESIGN: targets are restricted in code to loopback (127.0.0.0/8)
and RFC1918 private ranges (10/8, 172.16/12, 192.168/16). Public/routable
addresses are refused. This is a detection-test harness, not a flooding
weapon: it exists to trigger your own blue-team tooling in your own lab.
"""

import argparse
import ipaddress
import random
import sys
import time

try:
    from scapy.all import IP, TCP, ICMP, UDP, DNS, DNSQR, send
    SCAPY = True
except ImportError:
    SCAPY = False


def is_lab_target(ip_str):
    """Return True only for loopback or RFC1918 private addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


def require_lab_target(ip_str):
    """Exit unless the target is a loopback/private (lab) address."""
    if not is_lab_target(ip_str):
        print(f"[REFUSED] '{ip_str}' is not a lab target.")
        print("          Only loopback (127.0.0.0/8) and RFC1918 private ranges")
        print("          (10/8, 172.16/12, 192.168/16) are allowed by design.")
        sys.exit(2)


def build_syn(target, port):
    """Build a single SYN packet with a randomized source port."""
    return IP(dst=target) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")


def build_icmp(target):
    """Build a single ICMP echo-request packet."""
    return IP(dst=target) / ICMP()


def build_portscan(target, port):
    """Build a SYN packet aimed at a specific port (for scan patterns)."""
    return IP(dst=target) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")


def build_dns_query(target, domain):
    """Build a DNS query packet toward the target resolver."""
    return IP(dst=target) / UDP(sport=random.randint(1024, 65535), dport=53) / \
        DNS(rd=1, qd=DNSQR(qname=domain))


def run_attack(mode, target, port, count, delay):
    """Emit `count` packets of the chosen attack pattern toward the target."""
    if not SCAPY:
        print("[ERROR] scapy is required to send packets (pip install scapy).")
        sys.exit(1)

    print(f"[SIM] mode={mode} target={target} count={count} (lab-safe)")
    print("[SIM] Raw packet sending requires root. Point your IDS at this to see alerts.\n")

    sent = 0
    for i in range(count):
        if mode == "syn-flood":
            pkt = build_syn(target, port)
        elif mode == "icmp-flood":
            pkt = build_icmp(target)
        elif mode == "port-scan":
            pkt = build_portscan(target, (i % 1024) + 1)
        elif mode == "dns-flood":
            pkt = build_dns_query(target, random.choice(
                ["example.com", "test.lab", "a" * 20 + ".com"]))
        else:
            print(f"[ERROR] Unknown mode: {mode}")
            return

        try:
            send(pkt, verbose=0)
            sent += 1
        except PermissionError:
            print("[ERROR] Permission denied - run with sudo for raw sockets.")
            return
        except Exception as e:
            print(f"[ERROR] {e}")
            return

        if sent % 50 == 0:
            print(f"  [SENT] {sent}/{count}")
        if delay:
            time.sleep(delay)

    print(f"\n[SIM] Done. Sent {sent} packets to {target}.")


def main():
    parser = argparse.ArgumentParser(
        description="Attack-traffic simulator (lab-only; pairs with ids/firewall-simulator)"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP (loopback or RFC1918 private only)")
    parser.add_argument("-m", "--mode", default="syn-flood",
                        choices=["syn-flood", "icmp-flood", "port-scan", "dns-flood"],
                        help="Attack pattern (default: syn-flood)")
    parser.add_argument("-p", "--port", type=int, default=80,
                        help="Target port for SYN flood (default: 80)")
    parser.add_argument("-c", "--count", type=int, default=100,
                        help="Number of packets to send (default: 100)")
    parser.add_argument("-d", "--delay", type=float, default=0.0,
                        help="Delay between packets in seconds (default: 0)")
    args = parser.parse_args()

    require_lab_target(args.target)
    run_attack(args.mode, args.target, args.port, args.count, args.delay)


if __name__ == "__main__":
    main()
