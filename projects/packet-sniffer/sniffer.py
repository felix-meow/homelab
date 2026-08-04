#!/usr/bin/env python3
"""
Packet Sniffer - Robert Mircea
Homelab Project

A network packet sniffer built with Scapy for real-time traffic analysis.
Supports BPF filters and extracts HTTP, TCP, UDP, and ICMP details.
"""

import argparse
import json
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


class PacketSniffer:
    """Main packet sniffer class that handles capture and analysis."""

    def __init__(self):
        self.packets = []
        self.count = 0
        self.suspicious = []
        self.output_dir = "output"

    def packet_callback(self, packet):
        """
        Callback function called for each captured packet.
        Extracts and displays relevant information.
        """
        self.count += 1

        packet_info = {
            "timestamp": datetime.now().isoformat(),
            "number": self.count,
            "length": len(packet),
            "summary": packet.summary()
        }

        if IP in packet:
            ip = packet[IP]
            packet_info["src_ip"] = ip.src
            packet_info["dst_ip"] = ip.dst
            packet_info["protocol"] = ip.proto

            if TCP in packet:
                tcp = packet[TCP]
                packet_info["src_port"] = tcp.sport
                packet_info["dst_port"] = tcp.dport

                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode("utf-8", errors="ignore")
                        if "GET" in payload or "POST" in payload:
                            packet_info["http"] = self.extract_http(payload)
                    except Exception:
                        pass

            elif UDP in packet:
                udp = packet[UDP]
                packet_info["src_port"] = udp.sport
                packet_info["dst_port"] = udp.dport

            elif ICMP in packet:
                icmp = packet[ICMP]
                packet_info["icmp_type"] = icmp.type

        self.display_packet(packet_info)
        self.packets.append(packet_info)

    def extract_http(self, payload):
        """
        Extract HTTP method, path, and host from raw payload.
        """
        http_info = {}
        lines = payload.split("\n")
        for line in lines:
            if line.startswith("GET") or line.startswith("POST"):
                parts = line.split()
                if len(parts) >= 3:
                    http_info["method"] = parts[0]
                    http_info["path"] = parts[1]
            elif "Host:" in line:
                http_info["host"] = line.split(": ")[1]
        return http_info

    def display_packet(self, packet_info):
        """
        Print packet details in a human-readable format.
        """
        print(f"\n[PACKET] #{packet_info['number']} | {packet_info['timestamp']}")
        print(f"    Summary: {packet_info['summary']}")

        if "src_ip" in packet_info:
            print(f"    IP: {packet_info['src_ip']} -> {packet_info['dst_ip']}")
            print(f"    Protocol: {packet_info.get('protocol', 'Unknown')}")

            if "src_port" in packet_info:
                print(f"    Port: {packet_info['src_port']} -> {packet_info['dst_port']}")

            if "http" in packet_info:
                http = packet_info["http"]
                print(f"    HTTP: {http.get('method', '?')} {http.get('path', '?')}")
                if "host" in http:
                    print(f"    Host: {http['host']}")

        print(f"    Length: {packet_info['length']} bytes")

    def start(self, interface=None, filter_str=None, count=0):
        """
        Start packet capture with optional interface, filter, and count.
        """
        print(f"[SNIFF] Starting packet capture...")
        print(f"[SNIFF] Interface: {interface or 'default'}")
        print(f"[SNIFF] Filter: {filter_str or 'none'}")
        print(f"[SNIFF] Count: {count or 'infinite'}")
        print("[SNIFF] Press Ctrl+C to stop\n")

        try:
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self.packet_callback,
                count=count if count > 0 else None
            )
        except KeyboardInterrupt:
            print(f"\n[SNIFF] Captured {self.count} packets")
            self.save_report()

    def save_report(self):
        """
        Save captured packets to a JSON report.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        filename = f"{self.output_dir}/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, "w") as f:
            json.dump(self.packets, f, indent=2)

        print(f"[REPORT] Saved: {filename}")


def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer for Network Analysis")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture")
    parser.add_argument("-o", "--output", help="Output file (optional)")

    args = parser.parse_args()

    sniffer = PacketSniffer()
    sniffer.start(args.interface, args.filter, args.count)


if __name__ == "__main__":
    main()