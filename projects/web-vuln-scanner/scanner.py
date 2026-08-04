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
import json
import os
import re
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup


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

        self.test_xss()
        self.test_sqli()
        self.test_lfi()
        self.test_open_redirect()

        self.generate_report()

    def test_xss(self):
        """Test for reflected XSS vulnerabilities."""
        print("\n[TEST] XSS vulnerabilities...")
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
        ]

        for form in self.forms:
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

    def _add_vuln(self, vuln_type, url, details):
        """Add a vulnerability to the report."""
        vuln = {
            "type": vuln_type,
            "url": url,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        print(f"  [FOUND] {vuln_type} - {url}")

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


def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout (default: 10)")

    args = parser.parse_args()

    scanner = WebScanner(args.url, args.depth, args.timeout)
    scanner.scan_all()


if __name__ == "__main__":
    main()