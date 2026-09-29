#!/usr/bin/env python3
"""
Keylogger Detector - Robert Mircea
Homelab Project

Detects keyloggers and spyware through behavioral analysis of running
processes: suspicious imports, input-device access, and network exfiltration.
Supports a process whitelist, scheduled scanning, and JSON reporting.
"""

import os
import json
import argparse
import time
from datetime import datetime

import psutil

# Behavioral signatures.
SUSPICIOUS_IMPORTS = ["pynput", "keyboard", "evdev", "Xlib", "pyxhook"]
SUSPICIOUS_FILES = ["/dev/input/", "/dev/hidraw", "/proc/bus/input"]
SUSPICIOUS_HOOKS = ["SetWindowsHookEx", "XGrabKeyboard", "ioctl", "grab_keyboard"]
# Low-false-positive name/path hints (NOT generic words like "keyboard").
SUSPICIOUS_NAME_HINTS = ["keylog", "keystroke", "keygrab", "keycapture", "keysniff", "pyxhook"]
# Output files typical of a keylogger (behavioral, name-based).
SUSPICIOUS_LOG_PATTERNS = ["keylog", "keystroke", "captured_keys", "keys.txt", ".keys"]

# Process names known to be safe (baseline whitelist). Extendable via --whitelist.
DEFAULT_WHITELIST = {
    "ibus-daemon", "ibus-x11", "fcitx", "gnome-shell", "Xorg", "Xwayland",
    "pipewire", "pulseaudio",
}


def get_connections(proc):
    """Return process connections, using the non-deprecated API when available."""
    try:
        if hasattr(proc, "net_connections"):
            return proc.net_connections(kind="inet")
        return proc.connections(kind="inet")
    except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
        return []


def check_imports(cmdline):
    """Return True if the command line references a keylogging library."""
    if not cmdline:
        return False
    return any(imp in cmdline for imp in SUSPICIOUS_IMPORTS)


def check_open_files(proc):
    """Return True if the process has an input device open."""
    try:
        for file in proc.open_files():
            if any(sus in file.path for sus in SUSPICIOUS_FILES):
                return True
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return False


def check_log_files(proc):
    """Return True if the process has a keylog-like OUTPUT file open (behavioral)."""
    try:
        for file in proc.open_files():
            low = file.path.lower()
            if any(pat in low for pat in SUSPICIOUS_LOG_PATTERNS):
                return True
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return False


def check_script_name(proc_info, cmdline):
    """Return True only if a Python interpreter is running a .py script whose
    BASENAME hints at keylogging. Precise (no FP on shells or the detector itself)."""
    name = (proc_info.get("name") or "").lower()
    exe = (proc_info.get("exe") or "").lower()
    if "python" not in name and "python" not in exe:
        return False
    for tok in (cmdline or "").split():
        base = os.path.basename(tok).lower()
        if base.endswith(".py") and any(h in base for h in SUSPICIOUS_NAME_HINTS):
            return True
    return False


def _fd_flags(pid, fd):
    try:
        for line in open(f"/proc/{pid}/fdinfo/{fd}"):
            if line.startswith("flags:"):
                return int(line.split()[1], 8)
    except OSError:
        return None
    return None


def check_behavioral_capture(proc_info):
    """Name-independent runtime signature of a simple keylogger: a Python
    interpreter reading interactive input (stdin is a pipe/tty) while holding a
    writable regular file open in a user directory. Catches renamed keyloggers."""
    name = (proc_info.get("name") or "").lower()
    exe = (proc_info.get("exe") or "").lower()
    if "python" not in name and "python" not in exe:
        return False
    pid = proc_info.get("pid")
    fddir = f"/proc/{pid}/fd"
    try:
        try:
            stdin_target = os.readlink(f"{fddir}/0")
        except OSError:
            return False
        interactive = (stdin_target.startswith("pipe:") or "/dev/pts/" in stdin_target
                       or stdin_target.startswith("/dev/tty"))
        if not interactive:
            return False
        SYSTEM = ("/venv/", "site-packages", "/.cache/", "/usr/", "/proc/",
                  "/dev/", "/sys/", "/lib/", "/etc/")
        for fd in os.listdir(fddir):
            if fd in ("0", "1", "2"):
                continue
            try:
                tgt = os.readlink(f"{fddir}/{fd}")
            except OSError:
                continue
            if not tgt.startswith("/") or any(x in tgt for x in SYSTEM):
                continue
            flags = _fd_flags(pid, fd)
            if flags is None:
                continue
            if (flags & 3) in (1, 2):  # O_WRONLY / O_RDWR = writable
                return True
    except OSError:
        return False
    return False


def check_connections(proc):
    """Return True if the process has an established network connection."""
    for conn in get_connections(proc):
        if conn.status == psutil.CONN_ESTABLISHED:
            return True
    return False


def scan(whitelist, verbose=False):
    """Run a single behavioral scan and return the list of findings."""
    print("\n[SCAN] Caut keyloggere comportamentale...\n")
    findings = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
        try:
            info = proc.info
            cmdline = " ".join(info["cmdline"] or [])
            name = info["name"] or ""

            if name in whitelist:
                if verbose:
                    print(f"[SKIP] Whitelisted: {name} (PID {info['pid']})")
                continue

            score = 0
            reasons = []

            if check_imports(cmdline):
                score += 40
                reasons.append("Importă librării de keylogging")

            if check_open_files(proc):
                score += 30
                reasons.append("Accesează dispozitive de intrare")

            if check_connections(proc):
                score += 20
                reasons.append("Are conexiuni active")

            if check_log_files(proc):
                score += 30
                reasons.append("Scrie intr-un fisier de tip keylog")

            if check_script_name(info, cmdline):
                score += 50
                reasons.append("Ruleaza un script cu nume de keylogger")

            if check_behavioral_capture(info):
                score += 50
                reasons.append("Comportament de captura (stdin interactiv + fisier scris tinut deschis)")

            if verbose and score > 0:
                print(f"[DEBUG] {name} (PID {info['pid']}) score={score}")

            if score >= 50:
                findings.append({
                    "pid": info["pid"],
                    "name": name,
                    "cmdline": cmdline[:100],
                    "score": score,
                    "reasons": reasons,
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    if findings:
        print(f"[!] AM GĂSIT {len(findings)} PROCESE SUSPECTE:")
        print("-" * 60)
        for f in findings:
            print(f"PID: {f['pid']} | {f['name']}")
            print(f"Scor: {f['score']} | Motiv: {', '.join(f['reasons'])}")
            print(f"Cmd: {f['cmdline']}\n")
    else:
        print("[✓] Nu s-au găsit keyloggere comportamentale.")

    print(f"[✓] Scanare finalizată la {datetime.now().strftime('%H:%M:%S')}")
    return findings


def generate_report(findings, report_dir=None):
    """Write scan findings to <report_dir>/report.json (robust to read-only FS)."""
    report_dir = report_dir or os.environ.get("REPORT_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(findings),
        "risk_level": "HIGH" if findings else "SAFE",
        "findings": findings,
    }
    try:
        os.makedirs(report_dir, exist_ok=True)
        path = os.path.join(report_dir, "report.json")
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[REPORT] Saved: {path}")
    except OSError as e:
        print(f"[REPORT] Skipped (cannot write to '{report_dir}': {e})")


def load_whitelist(path):
    """Load additional whitelisted process names from a file (one per line)."""
    names = set(DEFAULT_WHITELIST)
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                name = line.strip()
                if name and not name.startswith("#"):
                    names.add(name)
    return names


def main():
    parser = argparse.ArgumentParser(description="Keylogger Detector")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("-w", "--whitelist", metavar="FILE",
                        help="File with process names to ignore (one per line)")
    parser.add_argument("--interval", type=int, metavar="SECONDS",
                        help="Run continuously, scanning every N seconds")
    args = parser.parse_args()

    whitelist = load_whitelist(args.whitelist)

    if args.interval:
        print(f"[MODE] Scheduled scanning every {args.interval}s (Ctrl+C to stop)")
        try:
            while True:
                findings = scan(whitelist, args.verbose)
                generate_report(findings)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[MODE] Stopped")
    else:
        findings = scan(whitelist, args.verbose)
        generate_report(findings)


if __name__ == "__main__":
    main()
