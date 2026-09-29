# Homelab Control Panel

A local Flask dashboard that **showcases and runs** the homelab security tools
(red-team + blue-team) from the browser, with live streaming output and a Stop
button. Built for fast access to the tools without typing CLI commands.

![teams](https://img.shields.io/badge/red%20%7C%20blue%20%7C%20recon-15%20tools-6ee7ff)

## Run

```bash
cd ~/homelab/webpanel
../venv/bin/python app.py
# open http://127.0.0.1:5000
```

The panel binds to **127.0.0.1 only**. Do not expose it to a network.

## What it does

- Lists every tool as a card, grouped **Red / Blue / Recon**, filterable.
- Each card has a form with the tool's real parameters (typed, with sensible
  defaults) and a **Run** button that executes the actual script and streams
  its output live into an in-card terminal.
- **Stop** button for long-running tools (WAF server, IDS/sniffer capture,
  chat server, MITM).

## Tools wired in

| Team | Tools |
|------|-------|
| Recon | port-scanner, web-vuln-scanner |
| Red | phishing-kit, password-cracker, ddos-simulator, mitm-proxy, keylogger *(on hold, disabled)* |
| Blue | waf-simulator, phishing-detector, firewall-simulator, file-integrity-monitor, keylogger-detector, ids, packet-sniffer, encrypted-chat (server) |

## Safety model

- Commands are built as **argv lists** from a fixed catalog and run **without a
  shell** (`shell=False`), so there is no shell-injection surface — only the
  catalogued tools can be launched, and parameters are validated by type.
- Root tools (`ids`, `packet-sniffer`, `ddos-simulator`, `mitm-proxy`) are run
  via `sudo`; they need passwordless sudo (as configured in this lab) or they
  will hang waiting for a password.
- Offensive tools keep their own guardrails: the DDoS simulator refuses public
  targets, the MITM proxy requires the authorization checkbox
  (`--i-own-this-target`). The panel does not bypass them.

## Files

```
webpanel/
├── app.py                # Flask backend + tool catalog + run/stream/stop API
├── requirements.txt
├── templates/index.html
├── static/style.css
├── static/app.js
└── demo_fim/             # sample dir for the File Integrity Monitor card
```

## Author

Robert Mircea — GitHub: felix-meow
