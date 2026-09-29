#!/usr/bin/env python3
"""
Port Scanner - Robert Mircea
Homelab Project

A TCP/UDP port scanner that identifies open services on a target host.
Supports single ports, ranges, and comma-separated lists, parallel scanning,
banner grabbing, service detection, and JSON/CSV export.
"""

import socket
import argparse
import json
import csv
import concurrent.futures
from datetime import datetime
from typing import List, Optional, Dict

# Common port -> service name mapping used for service detection.
COMMON_SERVICES: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp-submission", 631: "ipp",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


def detect_service(port: int) -> str:
    """Return the well-known service name for a port, or 'unknown'."""
    return COMMON_SERVICES.get(port, "unknown")


def grab_banner(host: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """
    Attempt to read a service banner from an open TCP port.

    For silent services (e.g. HTTP), a minimal probe is sent to elicit a
    response. Returns the decoded banner string, or None if none was read.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            try:
                # Many services (SSH, FTP, SMTP) send a banner immediately.
                data = sock.recv(1024)
                if not data:
                    # Silent service: nudge it with an HTTP-style probe.
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = sock.recv(1024)
            except socket.timeout:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
            return banner.splitlines()[0] if banner else None
    except Exception:
        return None


def scan_tcp(host: str, port: int, timeout: float = 1.0) -> bool:
    """Attempt a TCP connection to a port. Returns True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except Exception:
        return False


def scan_udp(host: str, port: int, timeout: float = 1.0) -> Optional[bool]:
    """
    Probe a UDP port. UDP is connectionless, so results are best-effort:
        - True  : a reply was received (open)
        - False : ICMP port-unreachable received (closed)
        - None  : no response (open|filtered)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (host, port))
            try:
                sock.recvfrom(1024)
                return True
            except socket.timeout:
                return None  # open|filtered
    except ConnectionRefusedError:
        return False
    except Exception:
        return None


def scan_port(host: str, port: int, timeout: float, protocol: str,
              banner: bool) -> Optional[dict]:
    """Scan a single port and return a result dict if it is open, else None."""
    if protocol == "udp":
        state = scan_udp(host, port, timeout)
        if state is False:
            return None
        status = "open" if state is True else "open|filtered"
    else:
        if not scan_tcp(host, port, timeout):
            return None
        status = "open"

    result = {
        "port": port,
        "protocol": protocol,
        "status": status,
        "service": detect_service(port),
        "banner": None,
    }
    if banner and protocol == "tcp":
        result["banner"] = grab_banner(host, port, timeout)
    return result


def parse_ports(port_string: str) -> List[int]:
    """
    Parse a port string into a list of integers.

    Supported formats: "80", "1-100", "22,80,443", "22,80-90,443".
    """
    ports: List[int] = []
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        elif part:
            ports.append(int(part))
    return ports


def export_json(host: str, results: List[dict], path: str) -> None:
    """Write scan results to a JSON file."""
    report = {
        "target": host,
        "timestamp": datetime.now().isoformat(),
        "open_ports": len(results),
        "results": results,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[EXPORT] JSON saved: {path}")


def export_csv(results: List[dict], path: str) -> None:
    """Write scan results to a CSV file."""
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["port", "protocol", "status", "service", "banner"]
        )
        writer.writeheader()
        writer.writerows(results)
    print(f"[EXPORT] CSV saved: {path}")


def main() -> None:
    """Main entry point for the port scanner."""
    parser = argparse.ArgumentParser(
        description="TCP/UDP Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py -H scanme.nmap.org
  python3 port_scanner.py -H 192.168.1.1 -p 22,80,443 --banner
  python3 port_scanner.py -H example.com -p 1-1024 --threads 200
  python3 port_scanner.py -H 192.168.1.1 -p 53,123 --protocol udp
  python3 port_scanner.py -H example.com --json out.json --csv out.csv
        """,
    )
    parser.add_argument("-H", "--host", required=True,
                        help="Target IP address or domain name")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range or list (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--protocol", choices=["tcp", "udp"], default="tcp",
                        help="Protocol to scan (default: tcp)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of parallel workers (default: 100)")
    parser.add_argument("--banner", action="store_true",
                        help="Grab service banners on open TCP ports")
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON")
    parser.add_argument("--csv", metavar="FILE", help="Export results to CSV")

    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[ERROR] Could not resolve host: {args.host}")
        return

    ports = parse_ports(args.ports)
    print(f"[SCAN] Target: {args.host} ({target_ip})")
    print(f"[SCAN] Protocol: {args.protocol.upper()}")
    print(f"[SCAN] Ports to scan: {len(ports)}")
    print(f"[SCAN] Workers: {args.threads} | Timeout: {args.timeout}s\n")

    # UDP over a large range is slow and unreliable: closed ports are inferred
    # from ICMP port-unreachable, which the OS rate-limits, so many closed ports
    # time out and show as "open|filtered" (false positives). Throttle + warn.
    workers = args.threads
    if args.protocol == "udp":
        workers = min(workers, 16)
        if len(ports) > 1024:
            print("[WARN] Large UDP scan: closed ports rely on ICMP port-unreachable,")
            print("[WARN] which the OS rate-limits -> many will show as 'open|filtered'")
            print("[WARN] (false positives) and each waits the full timeout. Prefer known")
            print("[WARN] UDP ports (e.g. 53,123,161,500) or a small range.\n")

    results: List[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, target_ip, port, args.timeout,
                            args.protocol, args.banner): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda r: r["port"])
    PRINT_CAP = 500  # keep CLI/panel output bounded even on a flood
    for r in results[:PRINT_CAP]:
        line = f"[OPEN] Port {r['port']}/{r['protocol']} ({r['service']}) {r['status']}"
        if r.get("banner"):
            line += f" | {r['banner']}"
        print(line)
    if len(results) > PRINT_CAP:
        print(f"[...] {len(results) - PRINT_CAP} more results suppressed (use --json for the full set)")

    open_ports = [r["port"] for r in results]
    shown = open_ports if len(open_ports) <= 100 else open_ports[:100]
    suffix = "" if len(open_ports) <= 100 else f" ... (+{len(open_ports) - 100} more)"
    print(f"\n[SUMMARY] Open ports: {shown}{suffix}")
    print(f"[SUMMARY] Total ports scanned: {len(ports)}")
    print(f"[SUMMARY] Total open ports: {len(open_ports)}")

    if args.json:
        export_json(args.host, results, args.json)
    if args.csv:
        export_csv(results, args.csv)


if __name__ == "__main__":
    main()
