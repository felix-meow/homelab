#!/usr/bin/env python3
"""
WAF Simulator - Robert Mircea
Homelab Project - blue-team pair for web-vuln-scanner

A signature-based Web Application Firewall. It inspects HTTP requests for
common attack payloads (XSS, SQLi, LFI / path traversal, command injection)
and blocks them with 403. Runs as a small reflecting server so the
web-vuln-scanner can be pointed at it to see its payloads get blocked.
"""

import argparse
import json
import os
import re
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

# Detection signatures grouped by attack class. Kept readable over exhaustive.
SIGNATURES = {
    "XSS": [
        r"<\s*script", r"onerror\s*=", r"onload\s*=", r"javascript:",
        r"<\s*img[^>]*src", r"<\s*svg", r"alert\s*\(",
    ],
    "SQLi": [
        r"'\s*or\s*'?1'?\s*=\s*'?1", r"union\s+select", r"--\s*$",
        r";\s*drop\s+table", r"'\s*--", r"\bor\b\s+1\s*=\s*1",
    ],
    "LFI/Path Traversal": [
        r"\.\./", r"\.\.\\", r"/etc/passwd", r"boot\.ini", r"win\.ini",
        r"php://", r"file://",
    ],
    "Command Injection": [
        r";\s*(cat|ls|id|whoami|uname)\b", r"\|\s*(cat|ls|id|nc|bash)\b",
        r"`[^`]+`", r"\$\([^)]+\)",
    ],
}

COMPILED = {
    cat: [re.compile(p, re.IGNORECASE) for p in pats]
    for cat, pats in SIGNATURES.items()
}


class WAF:
    """Signature-based request inspection engine."""

    def __init__(self, log_path="logs/waf.log"):
        self.log_path = log_path
        self.blocked = 0
        self.allowed = 0
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    def inspect(self, text):
        """Inspect a decoded string; return (category, pattern) on a hit, else None."""
        for category, patterns in COMPILED.items():
            for pattern in patterns:
                if pattern.search(text):
                    return category, pattern.pattern
        return None

    def evaluate_request(self, path, query, body):
        """Evaluate a full request. Returns (allowed: bool, reason: dict|None)."""
        # Decode once so URL-encoded payloads are inspected in clear text.
        surface = " ".join(unquote_plus(p) for p in (path, query, body) if p)
        hit = self.inspect(surface)
        if hit:
            category, pattern = hit
            self.blocked += 1
            reason = {"category": category, "pattern": pattern}
            self._log(path, query, body, reason)
            return False, reason
        self.allowed += 1
        return True, None

    def _log(self, path, query, body, reason):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "path": path,
            "query": query,
            "body": body[:200],
            "blocked_by": reason,
        }
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")


def make_handler(waf):
    """Build an HTTP handler bound to a WAF instance."""

    class WAFHandler(BaseHTTPRequestHandler):
        def _handle(self, body=""):
            parsed = urlparse(self.path)
            query = parsed.query
            allowed, reason = waf.evaluate_request(parsed.path, query, body)

            if not allowed:
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(
                    f"403 Forbidden - blocked by WAF ({reason['category']})".encode()
                )
                print(f"\033[91m[BLOCK]\033[0m {self.command} {self.path} "
                      f"-> {reason['category']} ({reason['pattern']})")
                return

            # Benign request: reflect input like a naive vulnerable backend would.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            reflected = unquote_plus(query + " " + body)
            self.wfile.write(f"<html><body>OK: {reflected}</body></html>".encode())
            print(f"\033[92m[ALLOW]\033[0m {self.command} {self.path}")

        def do_GET(self):
            self._handle()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="ignore") if length else ""
            self._handle(body)

        def log_message(self, *args):
            pass  # Silence default logging; we print our own verdicts.

    return WAFHandler


def run_server(host, port):
    """Run the WAF-protected reflecting server."""
    waf = WAF()
    server = HTTPServer((host, port), make_handler(waf))
    print(f"[WAF] Listening on http://{host}:{port}")
    print("[WAF] Malicious payloads -> 403, benign -> reflected. Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[WAF] Stopped. Blocked: {waf.blocked}, Allowed: {waf.allowed}")


def run_selftest():
    """Run a built-in set of payloads through the engine (no network needed)."""
    waf = WAF(log_path=os.path.join(os.environ.get("TMPDIR", "/tmp"), "waf_selftest.log"))
    cases = [
        ("benign", "/search", "q=hello world", ""),
        ("XSS", "/search", "q=<script>alert(1)</script>", ""),
        ("SQLi", "/login", "user=' OR '1'='1", ""),
        ("LFI", "/view", "file=../../../etc/passwd", ""),
        ("CMDi", "/ping", "host=8.8.8.8;cat /etc/passwd", ""),
        ("benign POST", "/comment", "", "text=nice article"),
        ("XSS POST", "/comment", "", "text=<img src=x onerror=alert(1)>"),
    ]
    print("[WAF] Self-test:\n")
    for label, path, query, body in cases:
        allowed, reason = waf.evaluate_request(path, query, body)
        verdict = "\033[92mALLOW\033[0m" if allowed else f"\033[91mBLOCK\033[0m ({reason['category']})"
        print(f"  {label:12} {verdict}")
    print(f"\n[WAF] Blocked {waf.blocked}, allowed {waf.allowed}")


def main():
    parser = argparse.ArgumentParser(description="WAF Simulator (pairs with web-vuln-scanner)")
    parser.add_argument("-m", "--mode", choices=["server", "selftest"], default="selftest",
                        help="Run mode (default: selftest)")
    parser.add_argument("--host", default="127.0.0.1", help="Server bind host")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Server port")
    args = parser.parse_args()

    if args.mode == "server":
        run_server(args.host, args.port)
    else:
        run_selftest()


if __name__ == "__main__":
    main()
