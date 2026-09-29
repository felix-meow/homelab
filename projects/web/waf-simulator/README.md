# WAF Simulator

Blue-team counterpart of the **web-vuln-scanner**. A signature-based Web
Application Firewall that inspects HTTP requests for common attack payloads
(XSS, SQLi, LFI / path traversal, command injection) and blocks them with a
`403`. Runs as a small reflecting server so the scanner can be pointed at it.

## Red vs Blue

| Offensive (pair) | Defensive (this) |
|------------------|------------------|
| web-vuln-scanner — fires XSS/SQLi/LFI payloads | waf-simulator — inspects and blocks them |

## Technologies

- Python 3.14+ (standard library only: `http.server`, `re`)

## Usage

```
python3 waf_simulator.py [OPTIONS]
```

| Option | Description |
|--------|-------------|
| -m, --mode | `selftest` (built-in payloads) or `server` (default: selftest) |
| --host | Server bind host (default: 127.0.0.1) |
| -p, --port | Server port (default: 8080) |

### Self-test (no network)

```
python3 waf_simulator.py -m selftest
```

Runs a fixed set of benign and malicious requests through the engine and prints
the ALLOW/BLOCK verdict for each.

### Server mode + web-vuln-scanner

```
# Terminal 1: start the WAF-protected reflecting server
python3 waf_simulator.py -m server -p 8080

# Terminal 2: scan it — malicious payloads come back as 403
python3 ../web-vuln-scanner/scanner.py -u http://127.0.0.1:8080 -d 1
```

Benign requests are reflected (`200`); requests carrying a known payload are
blocked (`403`) and logged to `logs/waf.log`.

## Detection classes

| Class | Examples blocked |
|-------|------------------|
| XSS | `<script>`, `onerror=`, `<svg>`, `javascript:` |
| SQLi | `' OR '1'='1`, `UNION SELECT`, `; DROP TABLE` |
| LFI / Path Traversal | `../`, `/etc/passwd`, `php://`, `file://` |
| Command Injection | `; cat`, `\| bash`, `` `...` ``, `$(...)` |

## Future Improvements

- Anomaly scoring (paranoia levels) in addition to signatures
- Rate limiting
- Custom rule import (ModSecurity-style)

## Author

Robert Mircea — GitHub: felix-meow
