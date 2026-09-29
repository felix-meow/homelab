#!/usr/bin/env python3
"""
Homelab Control Panel - Robert Mircea
A local Flask dashboard that showcases and *runs* the homelab security tools
(red-team and blue-team) from the browser, with live streaming output.

SAFETY / DESIGN
- Binds to 127.0.0.1 only (localhost). Do not expose this to a network.
- Commands are built as argv *lists* (never a shell string), from a fixed
  catalog with typed+validated parameters, so there is no shell-injection
  surface. Only the tools defined below can be launched.
- The offensive tools keep their own guardrails (ddos refuses public targets,
  mitm needs an explicit ownership ack). This panel does not bypass them.
"""

import json
import os
import re
import signal
import subprocess
import threading
import uuid
from queue import Queue

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

HOME = os.path.expanduser("~")
HOMELAB = os.path.join(HOME, "homelab")
PROJECTS = os.path.join(HOMELAB, "projects")
PYTHON = os.path.join(HOMELAB, "venv", "bin", "python")
if not os.path.exists(PYTHON):
    PYTHON = "python3"
DEMO_FIM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_fim")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# --------------------------------------------------------------------------- #
# Tool catalog. team: red | blue | recon. Each param: name, flag, type
# (str|int|float|choice|flag), default, optional required/choices/label/help.
# --------------------------------------------------------------------------- #
CATALOG = [
    {
        "id": "port-scanner", "name": "Port Scanner", "team": "recon",
        "dir": "network/port-scanner", "script": "port_scanner.py",
        "desc": "Scanner TCP/UDP pentru servicii deschise, cu banner grabbing.",
        "needs_root": False, "long_running": False,
        "params": [
            {"name": "host", "flag": "-H", "type": "str", "default": "127.0.0.1", "required": True, "label": "Host / IP"},
            {"name": "ports", "flag": "-p", "type": "str", "default": "1-1024", "label": "Porturi"},
            {"name": "timeout", "flag": "-t", "type": "float", "default": "0.5", "label": "Timeout (s)"},
            {"name": "protocol", "flag": "--protocol", "type": "choice", "choices": ["tcp", "udp"], "default": "tcp", "label": "Protocol"},
            {"name": "banner", "flag": "--banner", "type": "flag", "default": False, "label": "Banner grab"},
        ],
    },
    {
        "id": "web-vuln-scanner", "name": "Web Vuln Scanner", "team": "recon",
        "dir": "web/web-vuln-scanner", "script": "scanner.py",
        "desc": "Detecteaza XSS, SQLi, LFI, Open Redirect, CSRF, headere lipsa.",
        "needs_root": False, "long_running": True,
        "params": [
            {"name": "url", "flag": "-u", "type": "str", "default": "http://127.0.0.1:8080", "required": True, "label": "URL tinta"},
            {"name": "depth", "flag": "-d", "type": "int", "default": "1", "label": "Adancime crawl"},
            {"name": "timeout", "flag": "-t", "type": "int", "default": "10", "label": "Timeout (s)"},
        ],
    },
    {
        "id": "waf-simulator", "name": "WAF Simulator", "team": "blue",
        "dir": "web/waf-simulator", "script": "waf_simulator.py",
        "desc": "WAF pe semnaturi: blocheaza XSS/SQLi/LFI/CMDi. selftest sau server.",
        "needs_root": False, "long_running": True,
        "params": [
            {"name": "mode", "flag": "-m", "type": "choice", "choices": ["selftest", "server"], "default": "selftest", "label": "Mod"},
            {"name": "port", "flag": "-p", "type": "int", "default": "8080", "label": "Port (server)"},
            {"name": "vulnerable", "flag": "--vulnerable", "type": "flag", "default": False, "label": "Mod vulnerabil (WAF off)"},
        ],
    },
    {
        "id": "phishing-detector", "name": "Phishing Detector", "team": "blue",
        "dir": "phishing/phishing-detector", "script": "detector.py",
        "desc": "Scor de phishing: SPF/DKIM/DMARC, URL-uri, homoglife, urgenta.",
        "needs_root": False, "long_running": False,
        "params": [
            {"name": "subject", "flag": "-s", "type": "str", "default": "Urgent: Your account is suspended", "label": "Subiect"},
            {"name": "body", "flag": "-b", "type": "str", "default": "Verify now: http://paypal-verify.tk", "label": "Continut"},
            {"name": "from_addr", "flag": "--from", "type": "str", "default": "", "label": "From"},
            {"name": "reply_to", "flag": "--reply-to", "type": "str", "default": "", "label": "Reply-To"},
        ],
    },
    {
        "id": "phishing-kit", "name": "Phishing Kit", "team": "red",
        "dir": "phishing/phishing-kit", "script": "phishing_kit.py",
        "desc": "Genereaza mostre de phishing SINTETICE (nu trimite nimic).",
        "needs_root": False, "long_running": False,
        "params": [
            {"name": "template", "flag": "-t", "type": "choice", "choices": ["paypal", "bank", "delivery", "itsupport", "random"], "default": "paypal", "label": "Template"},
            {"name": "count", "flag": "-n", "type": "int", "default": "1", "label": "Numar"},
            {"name": "obfuscate", "flag": "--obfuscate", "type": "flag", "default": True, "label": "Domenii homoglife"},
        ],
    },
    {
        "id": "password-cracker", "name": "Password Cracker", "team": "red",
        "dir": "standalone/password-cracker", "script": "cracker.py",
        "desc": "Spargere hash-uri: dictionary, bruteforce, hybrid, rules.",
        "needs_root": False, "long_running": False,
        "params": [
            {"name": "target", "flag": "-t", "type": "str", "default": "5f4dcc3b5aa765d61d8327deb882cf99", "required": True, "label": "Hash tinta"},
            {"name": "algorithm", "flag": "-a", "type": "choice", "choices": ["auto", "md5", "sha1", "sha256", "sha512"], "default": "md5", "label": "Algoritm"},
            {"name": "method", "flag": "-m", "type": "choice", "choices": ["dictionary", "bruteforce", "hybrid", "rules"], "default": "dictionary", "label": "Metoda"},
            {"name": "max_length", "flag": "-l", "type": "int", "default": "4", "label": "Lungime max (bruteforce)"},
        ],
    },
    {
        "id": "firewall-simulator", "name": "Firewall Simulator", "team": "blue",
        "dir": "network/firewall-simulator", "script": "firewall.py",
        "desc": "Filtrare pe reguli cu prioritati; simulare trafic + raport.",
        "needs_root": False, "long_running": False,
        "params": [
            {"name": "simulate", "flag": "-s", "type": "int", "default": "20", "label": "Pachete simulate"},
            {"name": "list", "flag": "-l", "type": "flag", "default": False, "label": "Listeaza regulile"},
        ],
    },
    {
        "id": "file-integrity-monitor", "name": "File Integrity Monitor", "team": "blue",
        "dir": "standalone/file-integrity-monitor", "script": "fim.py",
        "desc": "Integritate fisiere pe SHA256: init baseline, verify, report.",
        "needs_root": False, "long_running": False,
        "params": [
            {"name": "directory", "flag": "-d", "type": "str", "default": DEMO_FIM, "required": True, "label": "Director"},
            {"name": "init", "flag": "--init", "type": "flag", "default": True, "label": "Init baseline"},
            {"name": "verify", "flag": "--verify", "type": "flag", "default": False, "label": "Verify vs baseline"},
            {"name": "report", "flag": "--report", "type": "flag", "default": False, "label": "Raport"},
        ],
    },
    {
        "id": "keylogger-detector", "name": "Keylogger Detector", "team": "blue",
        "dir": "keylogger/keylogger-detector", "script": "detector.py",
        "desc": "Detectie comportamentala de keyloggere (procese, /dev/input, retea).",
        "needs_root": False, "long_running": False,
        "params": [
            {"name": "verbose", "flag": "-v", "type": "flag", "default": False, "label": "Verbose"},
        ],
    },
    {
        "id": "ids", "name": "Intrusion Detection System", "team": "blue",
        "dir": "network/ids", "script": "ids_file.py",
        "desc": "IDS pe tcpdump: port scan, SYN/ICMP flood, brute force, ARP, DNS.",
        "needs_root": True, "long_running": True,
        "params": [
            {"name": "interface", "flag": "-i", "type": "str", "default": "lo", "label": "Interfata"},
            {"name": "time", "flag": "-t", "type": "int", "default": "15", "label": "Durata (s)"},
            {"name": "filter", "flag": "-f", "type": "str", "default": "", "label": "Filtru BPF"},
        ],
    },
    {
        "id": "packet-sniffer", "name": "Packet Sniffer", "team": "blue",
        "dir": "network/packet-sniffer", "script": "sniffer.py",
        "desc": "Captura live (Scapy): IP/TCP/UDP/ICMP, ARP-spoof, OS fingerprint.",
        "needs_root": True, "long_running": True,
        "params": [
            {"name": "interface", "flag": "-i", "type": "str", "default": "lo", "required": True, "label": "Interfata"},
            {"name": "count", "flag": "-c", "type": "int", "default": "10", "label": "Nr pachete"},
            {"name": "filter", "flag": "-f", "type": "str", "default": "", "label": "Filtru BPF"},
        ],
    },
    {
        "id": "ddos-simulator", "name": "DDoS Simulator", "team": "red",
        "dir": "network/ddos-simulator", "script": "ddos_simulator.py",
        "desc": "Genereaza trafic de atac (lab-safe: doar loopback/RFC1918).",
        "needs_root": True, "long_running": False,
        "warn": "Doar tinte de lab (127.0.0.0/8, 10/8, 172.16/12, 192.168/16). Tintele publice sunt refuzate.",
        "params": [
            {"name": "target", "flag": "-t", "type": "str", "default": "127.0.0.1", "required": True, "label": "Tinta (lab)"},
            {"name": "mode", "flag": "-m", "type": "choice", "choices": ["syn-flood", "icmp-flood", "port-scan", "dns-flood"], "default": "syn-flood", "label": "Mod"},
            {"name": "port", "flag": "-p", "type": "int", "default": "80", "label": "Port"},
            {"name": "count", "flag": "-c", "type": "int", "default": "100", "label": "Nr pachete"},
        ],
    },
    {
        "id": "mitm-proxy", "name": "MITM Proxy (ARP)", "team": "red",
        "dir": "network/mitm-proxy", "script": "mitm_proxy.py",
        "desc": "ARP spoofing intre victima si gateway. Necesita acord explicit.",
        "needs_root": True, "long_running": True,
        "warn": "LAN-local. Ruleaza DOAR pe retele pe care le detii/esti autorizat. Necesita bifa de autorizare.",
        "params": [
            {"name": "victim", "flag": "-v", "type": "str", "default": "", "required": True, "label": "Victima (IP LAN)"},
            {"name": "gateway", "flag": "-g", "type": "str", "default": "", "required": True, "label": "Gateway"},
            {"name": "interface", "flag": "-i", "type": "str", "default": "eth0", "required": True, "label": "Interfata"},
            {"name": "duration", "flag": "-d", "type": "int", "default": "30", "label": "Durata (s)"},
            {"name": "ack", "flag": "--i-own-this-target", "type": "flag", "default": False, "required": True, "label": "Confirm ca detin/sunt autorizat pe aceasta retea"},
        ],
    },
    {
        "id": "encrypted-chat", "name": "Encrypted Chat (server)", "team": "blue",
        "dir": "standalone/encrypted-chat", "script": "server.py",
        "desc": "Server chat E2E (AES-128/Fernet, handshake RSA). Clientul e CLI.",
        "needs_root": False, "long_running": True,
        "params": [
            {"name": "host", "flag": "--host", "type": "str", "default": "127.0.0.1", "label": "Bind host"},
            {"name": "port", "flag": "-p", "type": "int", "default": "5001", "label": "Port"},
            {"name": "password", "flag": "--password", "type": "str", "default": "chat123", "label": "Parola"},
        ],
    },
    {
        "id": "keylogger", "name": "Keylogger", "team": "red",
        "dir": "keylogger/keylogger", "script": "keylogger.py",
        "desc": "Componenta ofensiva - IN ASTEPTARE (on hold). Nu se ruleaza din panel.",
        "needs_root": False, "long_running": False, "disabled": True,
        "params": [],
    },
]
CATALOG_BY_ID = {t["id"]: t for t in CATALOG}

RUNS = {}  # run_id -> {proc, queue, returncode, needs_root}
RUNS_LOCK = threading.Lock()

app = Flask(__name__)


def build_argv(tool, raw):
    """Validate params and build the argv list + cwd. Raises ValueError on bad input."""
    argv = []
    if tool.get("needs_root"):
        argv.append("sudo")
    cwd = os.path.join(PROJECTS, tool["dir"])
    argv += [PYTHON, os.path.join(cwd, tool["script"])]

    for spec in tool["params"]:
        name, flag, ptype = spec["name"], spec["flag"], spec["type"]
        val = raw.get(name)

        if ptype == "flag":
            checked = bool(val)
            if spec.get("required") and not checked:
                raise ValueError(f"'{spec.get('label', name)}' este obligatoriu (bifeaza).")
            if checked:
                argv.append(flag)
            continue

        # value params
        if val is None or str(val).strip() == "":
            if spec.get("required"):
                raise ValueError(f"'{spec.get('label', name)}' este obligatoriu.")
            continue
        val = str(val).strip()

        if ptype == "int":
            if not re.fullmatch(r"-?\d+", val):
                raise ValueError(f"'{spec.get('label', name)}' trebuie sa fie numar intreg.")
        elif ptype == "float":
            if not re.fullmatch(r"-?\d+(\.\d+)?", val):
                raise ValueError(f"'{spec.get('label', name)}' trebuie sa fie numar.")
        elif ptype == "choice":
            if val not in spec["choices"]:
                raise ValueError(f"'{spec.get('label', name)}' valoare invalida.")
        # str: passed as a single argv element (no shell), so it is inert.
        argv += [flag, val]

    return argv, cwd


def _reader(run_id, proc):
    q = RUNS[run_id]["queue"]
    MAX_LINES = 5000  # backstop: never flood the browser, and stop runaway output
    n = 0
    for line in iter(proc.stdout.readline, ""):
        if n < MAX_LINES:
            q.put(ANSI_RE.sub("", line.rstrip("\n")))
            n += 1
        elif n == MAX_LINES:
            q.put(f"[output plafonat la {MAX_LINES} linii; opresc procesul]")
            n += 1
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        # beyond the cap: drain silently until the process exits
    proc.stdout.close()
    proc.wait()
    RUNS[run_id]["returncode"] = proc.returncode
    q.put(None)  # sentinel


@app.route("/")
def index():
    return render_template("index.html", catalog=CATALOG)


@app.route("/api/catalog")
def api_catalog():
    return jsonify(CATALOG)


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json(force=True)
    tool = CATALOG_BY_ID.get(data.get("id"))
    if not tool:
        return jsonify({"error": "Tool necunoscut."}), 404
    if tool.get("disabled"):
        return jsonify({"error": "Acest tool este on hold si nu poate fi rulat."}), 403
    try:
        argv, cwd = build_argv(tool, data.get("params", {}))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    run_id = uuid.uuid4().hex
    proc = subprocess.Popen(
        argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True,
    )
    with RUNS_LOCK:
        RUNS[run_id] = {"proc": proc, "queue": Queue(), "returncode": None,
                        "needs_root": tool.get("needs_root", False)}
    threading.Thread(target=_reader, args=(run_id, proc), daemon=True).start()

    # Display command with the long python path collapsed for readability.
    display = " ".join(argv).replace(PYTHON, "python").replace(cwd + "/", "")
    return jsonify({"run_id": run_id, "command": display})


@app.route("/api/stream/<run_id>")
def api_stream(run_id):
    run = RUNS.get(run_id)
    if not run:
        return jsonify({"error": "run inexistent"}), 404

    @stream_with_context
    def gen():
        q = run["queue"]
        while True:
            line = q.get()
            if line is None:
                yield f"event: end\ndata: {json.dumps({'returncode': run['returncode']})}\n\n"
                break
            yield f"data: {json.dumps(line)}\n\n"

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/stop/<run_id>", methods=["POST"])
def api_stop(run_id):
    run = RUNS.get(run_id)
    if not run:
        return jsonify({"error": "run inexistent"}), 404
    proc = run["proc"]
    if proc.poll() is None:
        try:
            pgid = os.getpgid(proc.pid)
            if run.get("needs_root"):
                # Child runs as root; kill the group via sudo.
                subprocess.run(["sudo", "kill", "-TERM", "--", f"-{pgid}"], check=False)
            else:
                os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    return jsonify({"stopped": True})


if __name__ == "__main__":
    print("[PANEL] Homelab Control Panel -> http://127.0.0.1:5000  (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=5000, threaded=True)
