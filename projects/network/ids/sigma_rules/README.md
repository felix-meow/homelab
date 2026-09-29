# Sigma Detection Rules

Detection rules for the homelab IDS, written in [Sigma](https://github.com/SigmaHQ/sigma)
so they can be converted to any SIEM backend (Elastic, Splunk, etc.) with
[`sigma-cli`](https://github.com/SigmaHQ/sigma-cli).

## Why these use the correlation spec

The IDS detects **thresholds over time** (e.g. "10 distinct ports in 10s"), not
single events. A lone SYN packet is not an attack. Each rule is therefore split
into:

1. a **base event** rule (`name:` referenced), matching one raw event, and
2. a **correlation** rule (`event_count` or `value_count`) that applies the
   threshold, `group-by`, and `timespan`.

This mirrors the Python engine in [`../ids_file.py`](../ids_file.py) exactly.

## Rule → IDS → MITRE ATT&CK mapping

| Sigma file | IDS rule | Threshold | ATT&CK |
|---|---|---|---|
| `ids_001_port_scan.yml` | IDS-001 | 10 distinct dst_ports / 10s | T1046 |
| `ids_002_bruteforce.yml` | IDS-002 | 5 conns to 22/21 / 30s | T1110 |
| `ids_003_icmp_flood.yml` | IDS-003 | 10 ICMP / 5s | T1498 |
| `ids_004_syn_flood.yml` | IDS-004 | 20 SYN / 5s | T1499, T1498 |
| `ids_006_dns_amplification.yml` | IDS-006 | 10 responses ≥200B / 5s | T1498.002 |
| *(engine only)* | IDS-005 ARP spoof | stateful MAC change | T1557.002 |

**IDS-005 (ARP spoofing)** is intentionally not a Sigma rule: it needs stateful
comparison of an IP's advertised MAC against a baseline, which Sigma's stateless
matching can't express. It lives in the detection engine. Knowing *what a rule
language can't do* is part of detection engineering.

## Convert to a backend

```bash
pip install sigma-cli
sigma convert -t elasticsearch -p ecs_windows ids_001_port_scan.yml
```

## Known limitations

- Field names (`event_type`, `src_ip`, `dst_port`, `response_size`) follow this
  lab's schema; map them to ECS/your pipeline before deploying.
- Network telemetry sees connection *attempts*, not auth *results* — IDS-002 is a
  proxy for brute force; pair with host `auth.log` for failure-based detection.
