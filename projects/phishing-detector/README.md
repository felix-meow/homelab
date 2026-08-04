# Phishing Detector

Analyzes emails for phishing attempts by checking headers, URLs, content, and language patterns.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates:

- Email header analysis (SPF, DKIM, DMARC)
- URL inspection
- Keyword detection
- Risk scoring
- Report generation

## Technologies

- Python 3.14+
- Regex
- urllib
- JSON

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/phishing-detector

pip install -r requirements.txt

## Usage

python3 detector.py [OPTIONS]

### Options

| Option | Description |
|--------|-------------|
| -s, --subject | Email subject |
| -b, --body | Email body |
| --from | From address |
| --reply-to | Reply-To address |
| -f, --file | JSON file containing email data |
| -o, --output | Output file (default: reports/report.json) |

### Examples

Quick analysis:
python3 detector.py -s "Urgent: Your account is suspended" -b "Click here: http://fake-bank.tk"

From JSON file:
python3 detector.py -f email.json

## Example Output

==================================================
[PHISHING] Analysis Results
==================================================
  Score: 65/100
  Status: SUSPICIOUS

  Findings:
    - [MEDIUM] Reply-To Mismatch
      Reply-To differs from From: hacker.com vs paypal.com
    - [HIGH] Suspicious URL
      Suspicious URL: http://paypal-verify.ga
    - [MEDIUM] Suspicious Keywords
      Suspicious keywords: verify, account, paypal

[REPORT] Saved: reports/report.json

## Detection Criteria

| Category | Score | Description |
|----------|-------|-------------|
| SPF/DKIM/DMARC fail | 20 | Authentication headers compromised |
| Reply-To mismatch | 15 | Reply-To differs from From |
| Suspicious URL | 25 | URL with suspicious domain |
| Suspicious Keywords | 5-30 | Phishing-specific words |
| Urgent Language | 10 | Words inducing panic |

## Report Example (JSON)

{
  "timestamp": "2026-08-04T16:00:00.123456",
  "score": 65,
  "max_score": 100,
  "suspicious": true,
  "findings": [
    {
      "type": "Suspicious URL",
      "severity": "HIGH",
      "message": "Suspicious URL: http://paypal-verify.ga"
    }
  ]
}

## Future Improvements

- n8n automation integration
- SPF/DKIM/DMARC validation
- Online domain blacklists
- Homoglyph detection
- HTML report generation
- VirusTotal API integration

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea