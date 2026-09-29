# DDoS / Attack-Traffic Simulator

Red-team counterpart of the **ids** and **firewall-simulator**. Generates
attack-pattern traffic (SYN flood, port scan, ICMP flood, DNS query burst) so
the blue-team tooling can be validated end to end.

## Lab-safe by design

Targets are restricted **in code** to loopback (`127.0.0.0/8`) and RFC1918
private ranges (`10/8`, `172.16/12`, `192.168/16`). Public / routable addresses
are refused with exit code 2. This is a detection-test harness for your own
lab — not a flooding tool for arbitrary targets. Raw packet sending requires
root.

## Red vs Blue

| Offensive (this) | Defensive (pair) |
|------------------|------------------|
| ddos-simulator — emits SYN/ICMP/scan/DNS bursts | ids (IDS-001/003/004/006), firewall-simulator |

## Technologies

- Python 3.14+, Scapy, `ipaddress`

## Usage

```
sudo python3 ddos_simulator.py -t <LAB_IP> -m <MODE> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| -t, --target | Target IP — **loopback or RFC1918 private only** |
| -m, --mode | syn-flood, icmp-flood, port-scan, dns-flood (default: syn-flood) |
| -p, --port | Target port for SYN flood (default: 80) |
| -c, --count | Number of packets to send (default: 100) |
| -d, --delay | Delay between packets in seconds (default: 0) |

### Example: trigger the IDS

```
# Terminal 1: run the IDS on the loopback interface
sudo python3 ../ids/ids_file.py -i lo -t 30

# Terminal 2: generate a SYN flood at localhost
sudo python3 ddos_simulator.py -t 127.0.0.1 -m syn-flood -c 200
```

The IDS should raise **IDS-004 (SYN Flood)** and/or **IDS-001 (Port Scan)**.
A public target is refused:

```
$ python3 ddos_simulator.py -t 8.8.8.8 -m syn-flood
[REFUSED] '8.8.8.8' is not a lab target.
```

## Attack patterns

| Mode | Pattern | Triggers |
|------|---------|----------|
| syn-flood | Many SYNs to one port | IDS-004 |
| port-scan | SYNs across many ports | IDS-001 |
| icmp-flood | ICMP echo requests | IDS-003 |
| dns-flood | DNS queries to :53 | IDS-006 (with responses) |

## Author

Robert Mircea — GitHub: felix-meow
