# Web Vulnerability Scanner

Automated web vulnerability scanner that detects XSS, SQLi, LFI, and Open Redirect vulnerabilities.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates:

- Web crawling and form extraction
- Vulnerability detection techniques
- HTTP request manipulation
- Report generation in JSON

## Technologies

- Python 3.14+
- Requests
- BeautifulSoup4
- LXML

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/web/web-vuln-scanner

pip install -r requirements.txt

## Usage

python3 scanner.py -u <URL> [-d DEPTH] [-t TIMEOUT]

### Options

| Option | Description |
|--------|-------------|
| -u, --url | Target URL (required) |
| -d, --depth | Crawl depth (default: 2) |
| -t, --timeout | Request timeout in seconds (default: 10) |
| --html FILE | Also write an HTML report |
| --markdown FILE | Also write a Markdown report |

In addition to XSS, SQLi, LFI, and Open Redirect, the scanner now also checks
for missing security headers, CSRF (POST forms without an anti-CSRF token), and
Remote File Inclusion (RFI), and shows a progress bar during testing.

### Examples

Basic scan:
python3 scanner.py -u http://testaspnet.vulnweb.com

Scan with depth 1:
python3 scanner.py -u http://testaspnet.vulnweb.com -d 1

Scan with custom timeout:
python3 scanner.py -u http://testaspnet.vulnweb.com -t 5

## Example Output

[SCAN] Starting vulnerability scan on http://testaspnet.vulnweb.com
==================================================
[CRAWL] http://testaspnet.vulnweb.com (depth 0)
[CRAWL] http://testaspnet.vulnweb.com/about.aspx (depth 1)

[STATS] Found 16 pages, 13 forms

[TEST] XSS vulnerabilities...
  [FOUND] XSS (Reflected POST) - http://testaspnet.vulnweb.com/login.aspx

==================================================
[REPORT] Scan completed
  Pages crawled: 16
  Forms tested: 13
  Vulnerabilities found: 13

[VULNERABILITIES]
  - XSS (Reflected POST): http://testaspnet.vulnweb.com/login.aspx

[REPORT] Saved: reports/report.json

## Report Example (JSON)

{
  "target": "http://testaspnet.vulnweb.com",
  "timestamp": "2026-08-04T13:10:10.094289",
  "stats": {
    "pages": 16,
    "forms": 13,
    "vulns": 13
  },
  "vulnerabilities": [
    {
      "type": "XSS (Reflected POST)",
      "url": "http://testaspnet.vulnweb.com/login.aspx",
      "details": "Payload: <script>alert(1)</script>",
      "timestamp": "2026-08-04T13:10:15.123456"
    }
  ]
}

## Test Targets

| Target | Description |
|--------|-------------|
| http://testaspnet.vulnweb.com | ASP.NET vulnerable test site |
| http://testhtml5.vulnweb.com | HTML5 vulnerable test site |
| http://zero.webappsecurity.com | Banking application demo |

## Implemented

- CSRF detection (missing anti-CSRF token on POST forms)
- RFI detection
- Security headers scan
- HTML report generation (`--html`)
- Markdown export (`--markdown`)
- Progress bar

## Future Improvements

- Intelligent fuzzing
- Wazuh SIEM integration

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea