#!/usr/bin/env python3
"""
Port Scanner - Robert Mircea
Homelab Project

A simple TCP port scanner that identifies open ports on a target host.
Supports single ports, ranges, and comma-separated lists.
"""

import socket
import argparse
from typing import List, Union


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Attempt a TCP connection to a specific port on a target host.

    Args:
        host: Target IP address or domain name.
        port: Port number to scan.
        timeout: Connection timeout in seconds.

    Returns:
        True if the port is open, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def parse_ports(port_string: str) -> List[int]:
    """
    Parse a port string into a list of integers.

    Supported formats:
        - Single port: "80"
        - Range: "1-100"
        - Comma-separated: "22,80,443"
        - Mixed: "22,80-90,443"

    Args:
        port_string: The port specification string.

    Returns:
        A list of port numbers.
    """
    ports = []

    if "," in port_string:
        for part in port_string.split(","):
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
    elif "-" in port_string:
        start, end = port_string.split("-")
        ports = list(range(int(start), int(end) + 1))
    else:
        ports = [int(port_string)]

    return ports


def main() -> None:
    """Main entry point for the port scanner."""
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py -H scanme.nmap.org
  python3 port_scanner.py -H 192.168.1.1 -p 22,80,443
  python3 port_scanner.py -H example.com -p 1-100
        """
    )
    parser.add_argument(
        "-H", "--host",
        required=True,
        help="Target IP address or domain name"
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port range or list (default: 1-1024)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"[SCAN] Target: {args.host}")
    print(f"[SCAN] Ports to scan: {len(ports)}")
    print(f"[SCAN] Timeout: {args.timeout}s\n")

    open_ports = []

    for port in ports:
        if scan_port(args.host, port, args.timeout):
            open_ports.append(port)
            print(f"[OPEN] Port {port} is open")
        else:
            print(f"[INFO] Port {port} is closed")

    print(f"\n[SUMMARY] Open ports: {open_ports}")
    print(f"[SUMMARY] Total ports scanned: {len(ports)}")
    print(f"[SUMMARY] Total open ports: {len(open_ports)}")


if __name__ == "__main__":
    main()