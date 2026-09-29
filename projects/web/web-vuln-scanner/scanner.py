#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Robert Mircea
Homelab Project

Automated web vulnerability scanner that detects:
- Reflected XSS
- SQL Injection
- Local File Inclusion (LFI)
- Open Redirect
"""

import argparse
import html
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

# Security headers every site should ideally set, with a short rationale.
SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS and data injection",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
    "Referrer-Policy": "Controls referrer leakage",
    "Permissions-Policy": "Restricts browser features",
}


class WebScanner:
    """Main web vulnerability scanner class."""

    def __init__(self, target_url, depth=2, timeout=10):
        self.target_url = target_url
        self.depth = depth
        self.timeout = timeout
        self.visited = set()
        self.forms = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def crawl(self, url, depth=0):
        """Recursively crawl the target URL for links and forms."""
        if depth > self.depth or url in self.visited:
            return

        self.visited.add(url)
        print(f"[CRAWL] {url} (depth {depth})")

        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract forms
            for form in soup.find_all("form"):
                action = form.get("action")
                method = form.get("method", "get").lower()
                form_url = urljoin(url, action) if action else url

                inputs = []
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    inp_type = inp.get("type", "text")
                    if name and inp_type not in ["submit", "button", "image"]:
                        inputs.append({
                            "name": name,
                            "type": inp_type,
                            "value": inp.get("value", "")
                        })

                self.forms.append({
                    "url": form_url,
                    "method": method,
                    "inputs": inputs,
                    "source": url
                })

            # Extract links
            for link in soup.find_all("a", href=True):
                href = link.get("href")
                if href and not href.startswith("#") and not href.startswith("javascript:"):
                    full_url = urljoin(url, href)
                    if full_url.startswith("http") and full_url not in self.visited:
                        self.crawl(full_url, depth + 1)

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {url}: {e}")

    def scan_all(self):
        """Run all vulnerability tests."""
        print(f"\n[SCAN] Starting vulnerability scan on {self.target_url}")
        print("=" * 50)

        self.crawl(self.target_url)
        print(f"\n[STATS] Found {len(self.visited)} pages, {len(self.forms)} forms")

        self.scan_security_headers()
        self.test_xss()
        self.test_sqli()
        self.test_lfi()
        self.test_open_redirect()
        self.test_rfi()
        self.test_csrf()

        self.generate_report()

    def _progress(self, label, current, total):
        """Render a simple in-place progress bar for a test phase."""
        if total == 0:
            return
        width = 30
        filled = int(width * current / total)
        bar = "#" * filled + "-" * (width - filled)
        sys.stdout.write(f"\r  [{label}] [{bar}] {current}/{total}")
        sys.stdout.flush()
        if current == total:
            sys.stdout.write("\n")

    def scan_security_headers(self):
        """Check the target's HTTP response for missing security headers."""
        print("\n[TEST] Security headers...")
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {e}")
            return

        for header, reason in SECURITY_HEADERS.items():
            if header not in resp.headers:
                self._add_vuln(
                    "Missing Security Header",
                    self.target_url,
                    f"{header} not set ({reason})",
                    severity="LOW",
                )

    def test_rfi(self):
        """Test for Remote File Inclusion by injecting a remote URL payload."""
        print("[TEST] Remote File Inclusion...")
        # Public, harmless marker resource; a vulnerable app would fetch and
        # reflect its contents.
        payloads = [
            "http://example.com/",
            "http://169.254.169.254/latest/meta-data/",
        ]
        markers = ["Example Domain", "ami-id", "instance-id"]

        for form in self.forms:
            if form["method"] != "get":
                continue
            for payload in payloads:
                params = self._prepare_params(form["inputs"], payload)
                test_url = f"{form['url']}?{params}"
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if any(m in resp.text for m in markers):
                        self._add_vuln("RFI", form["url"], f"Payload: {payload}")
                        break
                except requests.exceptions.RequestException:
                    pass

    def test_csrf(self):
        """Passively detect state-changing forms without an anti-CSRF token."""
        print("[TEST] CSRF (missing tokens)...")
        token_hints = ["csrf", "token", "authenticity", "nonce", "__requestverificationtoken"]

        for form in self.forms:
            if form["method"] != "post":
                continue
            has_token = any(
                any(hint in (inp["name"] or "").lower() for hint in token_hints)
                for inp in form["inputs"]
            )
            if not has_token:
                self._add_vuln(
                    "CSRF",
                    form["url"],
                    "POST form has no anti-CSRF token field",
                    severity="MEDIUM",
                )

    def test_xss(self):
        """Test for reflected XSS vulnerabilities."""
        print("\n[TEST] XSS vulnerabilities...")
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body onpageshow=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
        ]

        total = len(self.forms)
        for idx, form in enumerate(self.forms, 1):
            self._progress("XSS", idx, total)
            for payload in payloads:
                if form["method"] == "get":
                    params = self._prepare_params(form["inputs"], payload)
                    test_url = f"{form['url']}?{params}"
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout)
                        if self._check_payload_in_response(resp.text, payload):
                            self._add_vuln("XSS (Reflected GET)", form["url"], f"Payload: {payload}")
                            break
                    except:
                        pass

                elif form["method"] == "post":
                    data = self._prepare_dict(form["inputs"], payload)
                    try:
                        resp = self.session.post(form["url"], data=data, timeout=self.timeout)
                        if self._check_payload_in_response(resp.text, payload):
                            self._add_vuln("XSS (Reflected POST)", form["url"], f"Payload: {payload}")
                            break
                    except:
                        pass

    def test_sqli(self):
        """Test for SQL Injection vulnerabilities."""
        print("[TEST] SQL Injection vulnerabilities...")
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'/**/OR/**/1=1",
            "' OR 1=1-- -",
            "' AND 1=1--",
        ]

        for form in self.forms:
            for payload in payloads:
                if form["method"] == "get":
                    params = self._prepare_params(form["inputs"], payload)
                    test_url = f"{form['url']}?{params}"
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout)
                        if self._check_sql_error(resp.text):
                            self._add_vuln("SQL Injection (GET)", form["url"], f"Payload: {payload}")
                            break
                    except:
                        pass

                elif form["method"] == "post":
                    data = self._prepare_dict(form["inputs"], payload)
                    try:
                        resp = self.session.post(form["url"], data=data, timeout=self.timeout)
                        if self._check_sql_error(resp.text):
                            self._add_vuln("SQL Injection (POST)", form["url"], f"Payload: {payload}")
                            break
                    except:
                        pass

    def test_lfi(self):
        """Test for Local File Inclusion vulnerabilities."""
        print("[TEST] Local File Inclusion...")
        payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
        ]

        for form in self.forms:
            for payload in payloads:
                if form["method"] == "get":
                    params = self._prepare_params(form["inputs"], payload)
                    test_url = f"{form['url']}?{params}"
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout)
                        if "root:" in resp.text or "[extensions]" in resp.text:
                            self._add_vuln("LFI", form["url"], f"Payload: {payload}")
                            break
                    except:
                        pass

    def test_open_redirect(self):
        """Test for Open Redirect vulnerabilities."""
        print("[TEST] Open Redirect...")
        payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
        ]

        for form in self.forms:
            for payload in payloads:
                if form["method"] == "get":
                    params = self._prepare_params(form["inputs"], payload)
                    test_url = f"{form['url']}?{params}"
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                        if resp.status_code in [301, 302] and "evil.com" in resp.headers.get("Location", ""):
                            self._add_vuln("Open Redirect", form["url"], f"Payload: {payload}")
                            break
                    except:
                        pass

    def _prepare_params(self, inputs, payload):
        """Prepare GET parameters with payload."""
        params = []
        for inp in inputs:
            params.append(f"{inp['name']}={payload}")
        return "&".join(params)

    def _prepare_dict(self, inputs, payload):
        """Prepare POST data with payload."""
        data = {}
        for inp in inputs:
            data[inp["name"]] = payload
        return data

    def _check_payload_in_response(self, text, payload):
        """Check if payload is reflected in response."""
        return payload in text

    def _check_sql_error(self, text):
        """Check for SQL error indicators in response."""
        sql_errors = [
            "SQL syntax", "mysql", "SQLSTATE",
            "You have an error in your SQL",
            "Unclosed quotation mark",
            "Microsoft OLE DB",
            "PostgreSQL",
            "SQLite"
        ]
        return any(error.lower() in text.lower() for error in sql_errors)

    def _add_vuln(self, vuln_type, url, details, severity="HIGH"):
        """Add a vulnerability to the report."""
        vuln = {
            "type": vuln_type,
            "url": url,
            "details": details,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        print(f"  [FOUND] [{severity}] {vuln_type} - {url}")

    def generate_report(self):
        """Generate a JSON report of the scan results."""
        os.makedirs("reports", exist_ok=True)

        report = {
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "stats": {
                "pages": len(self.visited),
                "forms": len(self.forms),
                "vulns": len(self.vulnerabilities)
            },
            "vulnerabilities": self.vulnerabilities
        }

        with open("reports/report.json", "w") as f:
            json.dump(report, f, indent=2)

        print("\n" + "=" * 50)
        print("[REPORT] Scan completed")
        print(f"  Pages crawled: {len(self.visited)}")
        print(f"  Forms tested: {len(self.forms)}")
        print(f"  Vulnerabilities found: {len(self.vulnerabilities)}")

        if self.vulnerabilities:
            print("\n[VULNERABILITIES]")
            for v in self.vulnerabilities:
                print(f"  - {v['type']}: {v['url']}")

        print(f"\n[REPORT] Saved: reports/report.json")

    def generate_html_report(self, output_file):
        """Render the scan results as a standalone HTML report."""
        sev_colors = {"HIGH": "#c0392b", "MEDIUM": "#e67e22", "LOW": "#f1c40f"}
        rows = ""
        for v in self.vulnerabilities:
            sev = v.get("severity", "HIGH")
            rows += (
                f'<tr><td><span class="sev" style="background:{sev_colors.get(sev, "#999")}">'
                f'{html.escape(sev)}</span></td>'
                f'<td>{html.escape(v["type"])}</td>'
                f'<td>{html.escape(v["url"])}</td>'
                f'<td>{html.escape(v["details"])}</td></tr>\n'
            )

        doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Web Vulnerability Scan Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #222; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: .6rem; border-bottom: 1px solid #ddd; }}
  th {{ background: #f5f5f5; }}
  .sev {{ color:#fff; padding:.15rem .5rem; border-radius:4px; font-size:.8rem; }}
  .meta {{ color:#777; font-size:.85rem; }}
</style></head><body>
  <h1>Web Vulnerability Scan Report</h1>
  <p class="meta">Target: {html.escape(self.target_url)} &middot; Generated: {datetime.now().isoformat()}</p>
  <p>Pages crawled: {len(self.visited)} &middot; Forms tested: {len(self.forms)}
     &middot; Vulnerabilities: {len(self.vulnerabilities)}</p>
  <table><thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th></tr></thead>
  <tbody>
{rows if rows else '<tr><td colspan="4">No vulnerabilities found.</td></tr>'}
  </tbody></table>
</body></html>"""

        with open(output_file, "w") as f:
            f.write(doc)
        print(f"[REPORT] HTML saved: {output_file}")

    def generate_markdown_report(self, output_file):
        """Render the scan results as a Markdown report."""
        lines = [
            f"# Web Vulnerability Scan Report",
            "",
            f"- **Target:** {self.target_url}",
            f"- **Generated:** {datetime.now().isoformat()}",
            f"- **Pages crawled:** {len(self.visited)}",
            f"- **Forms tested:** {len(self.forms)}",
            f"- **Vulnerabilities found:** {len(self.vulnerabilities)}",
            "",
            "## Findings",
            "",
        ]
        if self.vulnerabilities:
            lines.append("| Severity | Type | URL | Detail |")
            lines.append("|----------|------|-----|--------|")
            for v in self.vulnerabilities:
                detail = v["details"].replace("|", "\\|")
                lines.append(
                    f"| {v.get('severity', 'HIGH')} | {v['type']} | {v['url']} | {detail} |"
                )
        else:
            lines.append("No vulnerabilities found.")
        lines.append("")

        with open(output_file, "w") as f:
            f.write("\n".join(lines))
        print(f"[REPORT] Markdown saved: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--html", metavar="FILE", help="Also write an HTML report")
    parser.add_argument("--markdown", metavar="FILE", help="Also write a Markdown report")

    args = parser.parse_args()

    scanner = WebScanner(args.url, args.depth, args.timeout)
    scanner.scan_all()

    if args.html:
        scanner.generate_html_report(args.html)
    if args.markdown:
        scanner.generate_markdown_report(args.markdown)


if __name__ == "__main__":
    main()