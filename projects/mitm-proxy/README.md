# MITM Proxy (ARP spoofing)

Red-team counterpart of the **packet-sniffer** and **ids** ARP-spoof detection
(IDS-005). Performs bidirectional ARP-cache poisoning between a victim and the
gateway on the local segment, then passively logs intercepted HTTP requests.
ARP tables are restored on exit.

## Authorization

ARP spoofing only works on the local L2 segment, so this is inherently
LAN-local. It still requires an explicit `--i-own-this-target` acknowledgement
and prints a warning, because running it against machines you do not own is
illegal. Use it only on networks you own or are authorized to test. Requires
root.

## Red vs Blue

| Offensive (this) | Defensive (pair) |
|------------------|------------------|
| mitm-proxy — poisons victim/gateway ARP caches | packet-sniffer ARP detection, ids IDS-005 |

## Technologies

- Python 3.14+, Scapy

## Usage

```
sudo python3 mitm_proxy.py -v <VICTIM_IP> -g <GATEWAY_IP> -i <IFACE> --i-own-this-target
```

| Option | Description |
|--------|-------------|
| -v, --victim | Victim IP (on your LAN) |
| -g, --gateway | Gateway IP |
| -i, --interface | Network interface |
| -d, --duration | Duration in seconds (default: 60) |
| --i-own-this-target | Required acknowledgement of authorization |

Without the acknowledgement flag the tool refuses to run (exit code 2).

### Example: trigger ARP-spoof detection

```
# Terminal 1: run the sniffer / IDS on the LAN interface
sudo python3 ../packet-sniffer/sniffer.py -i eth0

# Terminal 2: start the MITM against a lab host
sudo python3 mitm_proxy.py -v 192.168.1.50 -g 192.168.1.1 -i eth0 \
     --i-own-this-target -d 30
```

The sniffer should print an **ARP spoofing** alert (and the IDS **IDS-005**) as
the victim's advertised MAC changes to the attacker's.

## How it works

1. Resolve victim and gateway MACs via ARP requests.
2. Enable kernel IP forwarding so traffic keeps flowing (transparent MITM).
3. Repeatedly send forged ARP replies: tell the victim we are the gateway and
   tell the gateway we are the victim.
4. Passively log intercepted HTTP request lines.
5. On exit, restore both ARP caches and disable IP forwarding.

## Author

Robert Mircea — GitHub: felix-meow
