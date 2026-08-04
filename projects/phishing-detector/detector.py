#!/usr/bin/env python3
"""
Phishing Detector - Robert Mircea
Homelab Project

Analyzes emails for phishing attempts by checking headers, URLs, content, and language patterns.
"""

import argparse
import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse


class PhishingDetector:
    """Phishing detection engine for email analysis."""

    def __init__(self):
        self.findings = []
        self.score = 0
        self.max_score = 100

        # Suspicious keywords
        self.suspicious_words = [
            'verify', 'confirm', 'update', 'validate', 'security',
            'account', 'suspend', 'unusual', 'login', 'password',
            'bank', 'paypal', 'amazon', 'apple', 'microsoft',
            'alert', 'warning', 'urgent', 'immediate', 'action',
            'click here', 'link below', 'attached', 'invoice',
            'refund', 'charge', 'suspicious', 'unauthorized'
        ]

        # Urgency indicators
        self.urgency_words = ['immediate', 'urgent', 'within 24 hours', 'today', 'asap', 'now']

        # Suspicious TLDs
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.io', '.top', '.xyz', '.club']

        # Known legitimate domains (for comparison)
        self.legitimate_domains = [
            'paypal.com', 'amazon.com', 'apple.com', 'microsoft.com',
            'google.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'bankofamerica.com', 'chase.com', 'wellsfargo.com'
        ]

    def analyze_email(self, email_data):
        """Main analysis method that processes an email."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'score': 0,
            'max_score': self.max_score,
            'findings': [],
            'suspicious': False
        }

        # Analyze headers
        if 'headers' in email_data:
            header_results = self._analyze_headers(email_data['headers'])
            results['score'] += header_results['score']
            results['findings'].extend(header_results['findings'])

        # Analyze URLs
        if 'body' in email_data:
            url_results = self._analyze_urls(email_data['body'])
            results['score'] += url_results['score']
            results['findings'].extend(url_results['findings'])

        # Analyze content
        content_results = self._analyze_content(email_data)
        results['score'] += content_results['score']
        results['findings'].extend(content_results['findings'])

        results['score'] = min(results['score'], self.max_score)
        results['suspicious'] = results['score'] > 50
        results['findings'] = results['findings'][:20]  # Limit findings

        return results

    def _analyze_headers(self, headers):
        """Analyze email headers for spoofing indicators."""
        result = {'score': 0, 'findings': []}

        from_addr = headers.get('from', '')
        reply_to = headers.get('reply-to', '')

        # Check SPF
        if 'spf' in headers and 'fail' in headers['spf'].lower():
            result['score'] += 20
            result['findings'].append({
                'type': 'SPF',
                'severity': 'HIGH',
                'message': 'SPF check failed'
            })

        # Check DKIM
        if 'dkim' in headers and 'fail' in headers['dkim'].lower():
            result['score'] += 20
            result['findings'].append({
                'type': 'DKIM',
                'severity': 'HIGH',
                'message': 'DKIM check failed'
            })

        # Check DMARC
        if 'dmarc' in headers and 'fail' in headers['dmarc'].lower():
            result['score'] += 20
            result['findings'].append({
                'type': 'DMARC',
                'severity': 'HIGH',
                'message': 'DMARC check failed'
            })

        # Check Reply-To mismatch
        if from_addr and reply_to and from_addr != reply_to:
            from_domain = self._extract_domain(from_addr)
            reply_domain = self._extract_domain(reply_to)
            if from_domain and reply_domain and from_domain != reply_domain:
                result['score'] += 15
                result['findings'].append({
                    'type': 'Reply-To Mismatch',
                    'severity': 'MEDIUM',
                    'message': f"Reply-To differs from From: {reply_domain} vs {from_domain}"
                })

        return result

    def _analyze_urls(self, text):
        """Extract and analyze URLs in the email body."""
        result = {'score': 0, 'findings': []}

        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)

        for url in urls:
            url_info = self._check_url(url)
            if url_info['suspicious']:
                result['score'] += 25
                result['findings'].append({
                    'type': 'Suspicious URL',
                    'severity': 'HIGH',
                    'message': f"Suspicious URL: {url}",
                    'url_info': url_info
                })
                break  # One suspicious URL is enough

        return result

    def _check_url(self, url):
        """Check a URL for suspicious characteristics."""
        result = {'url': url, 'suspicious': False, 'reasons': []}

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove www.
        if domain.startswith('www.'):
            domain = domain[4:]

        # Check for IP address
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            result['suspicious'] = True
            result['reasons'].append('IP address used instead of domain')

        # Check suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                result['suspicious'] = True
                result['reasons'].append(f'Suspicious TLD: {tld}')

        # Check for domain similarity
        for legit in self.legitimate_domains:
            if legit in domain and domain != legit:
                result['suspicious'] = True
                result['reasons'].append(f'Domain similar to: {legit}')

        # Check URL shorteners
        if any(short in domain for short in ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly']):
            result['suspicious'] = True
            result['reasons'].append('URL shortener detected')

        return result

    def _analyze_content(self, email_data):
        """Analyze the email content for phishing indicators."""
        result = {'score': 0, 'findings': [], 'keywords': []}

        text = (email_data.get('subject', '') + ' ' + email_data.get('body', '')).lower()

        # Check for suspicious keywords
        found_keywords = []
        for word in self.suspicious_words:
            if word in text:
                found_keywords.append(word)

        if found_keywords:
            result['score'] += min(len(found_keywords) * 5, 30)
            result['findings'].append({
                'type': 'Suspicious Keywords',
                'severity': 'MEDIUM',
                'message': f"Suspicious keywords: {', '.join(found_keywords[:5])}"
            })

        # Check for urgency indicators
        for word in self.urgency_words:
            if word in text:
                result['score'] += 10
                result['findings'].append({
                    'type': 'Urgent Language',
                    'severity': 'MEDIUM',
                    'message': f'Urgency indicator: "{word}"'
                })
                break

        return result

    def _extract_domain(self, email):
        """Extract domain from an email address."""
        match = re.search(r'@([^\s>]+)', email)
        if match:
            return match.group(1)
        return None

    def generate_report(self, results, output_file='reports/report.json'):
        """Generate a JSON report of the analysis."""
        os.makedirs('reports', exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n[REPORT] Saved: {output_file}")
        print("\n" + "=" * 50)
        print("[PHISHING] Analysis Results")
        print("=" * 50)
        print(f"  Score: {results['score']}/100")
        print(f"  Status: {'SUSPICIOUS' if results['suspicious'] else 'SAFE'}")

        if results['findings']:
            print("\n  Findings:")
            for finding in results['findings'][:10]:
                print(f"    - [{finding['severity']}] {finding['type']}")
                print(f"      {finding['message']}")


def main():
    parser = argparse.ArgumentParser(description="Phishing Detector")
    parser.add_argument("-s", "--subject", help="Email subject")
    parser.add_argument("-b", "--body", help="Email body")
    parser.add_argument("--from", dest="from_addr", help="From address")
    parser.add_argument("--reply-to", dest="reply_to", help="Reply-To address")
    parser.add_argument("-f", "--file", help="JSON file containing email data")
    parser.add_argument("-o", "--output", default="reports/report.json", help="Output file")

    args = parser.parse_args()

    detector = PhishingDetector()

    if args.file:
        with open(args.file, 'r') as f:
            email_data = json.load(f)
    else:
        email_data = {
            'subject': args.subject or '',
            'body': args.body or '',
            'headers': {
                'from': args.from_addr or '',
                'reply-to': args.reply_to or ''
            }
        }

    results = detector.analyze_email(email_data)
    detector.generate_report(results, args.output)


if __name__ == "__main__":
    main()