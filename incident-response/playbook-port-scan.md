# Incident Response Playbook - Port Scan Detection

**Scope:** Detection, triage, investigation, and response for network port-scanning
activity against monitored hosts.
**Detection source:** Custom Python IDS (`projects/network/ids/ids_file.py`), rule
**IDS-001 Port Scan**, plus the matching Sigma rule
`projects/network/ids/sigma_rules/ids_001_port_scan.yml`.
**MITRE ATT&CK:** T1046 - Network Service Discovery (Reconnaissance / Discovery).

---

## 1. Detection logic

The IDS flags a port scan when a single source contacts many distinct destination
ports on the same host in a short window:

| Parameter | Value |
|-----------|-------|
| Rule ID | IDS-001 |
| Threshold | >= 10 distinct destination ports |
| Time window | 10 seconds |
| Group-by | `src_ip`, `dst_ip` |
| Severity | HIGH |

Alert payload fields: `rule_id`, `rule_name`, `severity`, `src_ip`, `dst_ip`,
`ports`, `count`, `timestamp`. Alerts are appended to `alerts/alerts.log` and
forwarded (non-blocking) to an n8n webhook, which maps them into a TheHive alert.

---

## 2. Severity & triage criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Scan from **internal** host toward internal assets | HIGH | Possible lateral movement / compromised host - investigate now |
| Scan from **external** IP toward exposed services | MEDIUM-HIGH | Expected internet background noise, but confirm no follow-on exploitation |
| Source matches a known scanner / asset-inventory host | INFO | Confirm against allowlist, tune rule, close |

**First question:** is the source internal or external? Internal scanning is the
higher-priority case (it often means an already-compromised host enumerating the
network).

---

## 3. Triage - confirm true vs false positive (target: 5 min)

1. Open the alert in TheHive (or `alerts/alerts.log`); note `src_ip`, `dst_ip`,
   `ports`, `count`, `timestamp`.
2. Check the source against the **allowlist** (vuln scanners, monitoring, asset
   inventory). If allowlisted -> tune rule, mark false positive, close.
3. Confirm the pattern is a scan, not a legitimate NATed client generating many
   connections. Look at port spread: sequential/wide port ranges = scan; a few
   repeated app ports = likely benign.

---

## 4. Investigation

1. **Scope the source.** Pull all events for `src_ip` in the window. Did the same
   source hit multiple destinations (horizontal sweep) or many ports on one host
   (vertical scan)?
2. **Correlate.** Cross-check firewall / connection logs for the same `src_ip`:
   which ports actually connected vs were refused?
3. **Look for follow-on activity.** After recon, attackers move to exploitation.
   Check for IDS-002 (brute force), service exploitation attempts, or new sessions
   from the source shortly after the scan.
4. **Enrich external sources** with OSINT: `whois`, AbuseIPDB, threat-intel
   reputation. Known-bad -> raise priority.
5. **Assess exposure.** For the targeted ports, are any services actually running
   and reachable? An open, unpatched service is the real risk, not the scan itself.

---

## 5. Containment

- **Internal source:** isolate the host (network quarantine / VLAN), preserve
  volatile data for forensics, treat as potentially compromised.
- **External source:** block the `src_ip` at the perimeter firewall if the scan is
  aggressive or paired with exploitation attempts; rate-limit otherwise.

## 6. Eradication & remediation

- If a host was compromised: identify entry vector, remove persistence, rebuild if
  integrity is uncertain.
- Reduce attack surface on the targeted host: close unnecessary ports, patch
  exposed services, enforce firewall rules (least exposure).

## 7. Recovery

- Restore isolated hosts after verification.
- Confirm normal traffic patterns resume and no residual alerts fire from the same
  source.

---

## 8. Escalation criteria

Escalate to senior IR / management when any of the following is true:
- Source is an **internal** host (possible active compromise).
- Scan is immediately followed by **successful** exploitation or authentication.
- Multiple internal hosts are targeted (network-wide sweep).
- The targeted service handles sensitive data.

## 9. Reporting

Document the incident with: timeline (detection -> triage -> response), affected
hosts and ports, source attribution/OSINT, impact assessment, actions taken, and
remediation recommendations. Keep evidence (alert JSON, correlated log excerpts).

## 10. Post-incident & retest

- Apply the agreed remediation (close ports / patch / firewall rule).
- **Retest**: re-run a controlled scan against the host and confirm the exposure
  is gone and the detection still fires (validates both the fix and the rule).
- Tune IDS-001 thresholds / allowlist to reduce false positives; record the change.

---

## Automation (SOAR)

IDS alert -> n8n webhook -> mapped to a TheHive alert (analyst-ready), so triage
starts from a structured case instead of a raw log line. See
`n8n-workflows/ids-to-thehive.json`.

## References

- MITRE ATT&CK T1046 - Network Service Discovery
- IDS rule: `projects/network/ids/ids_file.py` (IDS-001)
- Sigma: `projects/network/ids/sigma_rules/ids_001_port_scan.yml`
