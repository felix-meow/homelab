#!/usr/bin/env python3
"""
Keylogger Detector - Robert Mircea
Homelab Project

Detects keyloggers and spyware by analyzing running processes, files, and network connections.
"""

import os
import psutil
import re
import json
import argparse
from datetime import datetime


class KeyloggerDetector:
    """Keylogger detection engine using process, file, and network analysis."""

    def __init__(self):
        self.findings = []
        self.score = 0
        self.suspicious_processes = []
        self.suspicious_files = []
        self.suspicious_connections = []

        # Known keylogger process names
        self.known_keyloggers = [
            'keylog.exe', 'keylogger.exe', 'hook.exe',
            'spy.exe', 'record.exe', 'capture.exe',
            'klog.exe', 'snoop.exe', 'watch.exe',
            'hklm.exe', 'logkeys', 'uberkey'
        ]

        # Suspicious keywords in process names/arguments
        self.suspicious_keywords = [
            'keylog', 'hook', 'keyboard', 'input', 'capture',
            'logger', 'spy', 'monitor', 'record', 'stealth'
        ]

        # Suspicious code patterns
        self.suspicious_patterns = [
            r'keylog',
            r'keyboard.*hook',
            r'input.*capture',
            r'log.*key',
            r'key.*log',
            r'GetKeyState',
            r'GetAsyncKeyState',
            r'SetWindowsHookEx',
            r'WH_KEYBOARD',
            r'WH_KEYBOARD_LL'
        ]

        # Directories to exclude from file scanning
        self.exclude_dirs = [
            'node_modules', '.git', '__pycache__', '.cache',
            '.local', '.config', '.vscode', '.docker',
            'venv', 'site-packages', '.npm', '.nvm'
        ]

        # Extensions to exclude
        self.exclude_extensions = [
            '.pyc', '.pyo', '.so', '.dll', '.dylib',
            '.png', '.jpg', '.jpeg', '.gif', '.ico',
            '.mp3', '.mp4', '.wav', '.flac',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.zip', '.tar', '.gz', '.bz2',
            '.map', '.min.js', '.min.css', '.tsbuildinfo'
        ]

    def should_exclude(self, path):
        """Check if a file or directory should be excluded from scanning."""
        for excluded in self.exclude_dirs:
            if excluded in path:
                return True

        for ext in self.exclude_extensions:
            if path.endswith(ext):
                return True

        if path.startswith('/var/log'):
            return True

        return False

    def scan_processes(self):
        """Scan running processes for keylogger indicators."""
        print("[SCAN] Processes...")

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                name = proc.info['name'].lower()
                exe = proc.info['exe'] or ''
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()

                # Check known keylogger names
                if name in self.known_keyloggers:
                    self.add_finding(
                        'HIGH',
                        f"Known keylogger process: {name}",
                        {'pid': proc.info['pid'], 'name': name}
                    )
                    continue

                # Check suspicious keywords
                for keyword in self.suspicious_keywords:
                    if keyword in name or keyword in cmdline:
                        self.add_finding(
                            'MEDIUM',
                            f"Suspicious keyword '{keyword}' in process: {name}",
                            {'pid': proc.info['pid'], 'name': name}
                        )
                        break

                # Check if running from temp
                if 'temp' in exe.lower() or 'tmp' in exe.lower():
                    if 'keyboard' in cmdline or 'hook' in cmdline:
                        self.add_finding(
                            'HIGH',
                            f"Process running from temp with suspicious cmdline: {name}",
                            {'pid': proc.info['pid'], 'name': name, 'exe': exe}
                        )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        print(f"[STATS] Found {len(self.suspicious_processes)} suspicious processes")

    def scan_files(self):
        """Scan files for keylogger code patterns."""
        print("[SCAN] Files...")

        directories = [
            os.path.expanduser('~'),
            '/tmp'
        ]

        scanned = 0

        for directory in directories:
            if not os.path.exists(directory):
                continue

            for root, dirs, files in os.walk(directory):
                # Skip excluded directories
                should_skip = False
                for excluded in self.exclude_dirs:
                    if excluded in root:
                        should_skip = True
                        break
                if should_skip:
                    continue

                for file in files:
                    filepath = os.path.join(root, file)

                    if self.should_exclude(filepath):
                        continue

                    try:
                        if os.path.getsize(filepath) < 50000:  # < 50KB
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read()
                                for pattern in self.suspicious_patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        self.add_finding(
                                            'HIGH',
                                            f"Found keylogger code in: {filepath}",
                                            {'file': filepath, 'pattern': pattern}
                                        )
                                        break

                        scanned += 1
                        if scanned % 100 == 0:
                            print(f"  [PROGRESS] Scanned {scanned} files...")

                    except (IOError, OSError, UnicodeDecodeError):
                        pass

        print(f"[STATS] Found {len(self.suspicious_files)} suspicious files")

    def check_network_connections(self):
        """Check network connections for suspicious activity."""
        print("[SCAN] Network connections...")

        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                try:
                    pid = conn.pid
                    proc = psutil.Process(pid)
                    proc_name = proc.name().lower()

                    # Check if process is suspicious
                    is_suspicious = False
                    for keyword in self.suspicious_keywords:
                        if keyword in proc_name:
                            is_suspicious = True
                            break

                    if proc_name in self.known_keyloggers:
                        is_suspicious = True

                    if is_suspicious:
                        self.add_finding(
                            'HIGH',
                            f"Suspicious process {proc_name} (PID: {pid}) has network connection to {conn.raddr}",
                            {'pid': pid, 'process': proc_name, 'connection': str(conn.raddr)}
                        )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        print(f"[STATS] Found {len(self.suspicious_connections)} suspicious connections")

    def add_finding(self, severity, message, details=None):
        """Add a finding and update the risk score."""
        finding = {
            'severity': severity,
            'message': message,
            'details': details or {},
            'timestamp': datetime.now().isoformat()
        }

        self.findings.append(finding)

        if severity == 'HIGH':
            self.score += 30
        elif severity == 'MEDIUM':
            self.score += 15
        elif severity == 'LOW':
            self.score += 5

        # Categorize finding
        if 'pid' in str(details) or 'process' in str(details):
            self.suspicious_processes.append(finding)
        elif 'file' in str(details):
            self.suspicious_files.append(finding)
        else:
            self.suspicious_connections.append(finding)

        # Print to console
        colors = {'HIGH': '\033[91m', 'MEDIUM': '\033[93m', 'LOW': '\033[94m'}
        color = colors.get(severity, '\033[0m')
        reset = '\033[0m'

        print(f"  {color}[{severity}]{reset} {message}")

    def generate_report(self):
        """Generate a JSON report of all findings."""
        os.makedirs('reports', exist_ok=True)

        report = {
            'timestamp': datetime.now().isoformat(),
            'score': min(self.score, 100),
            'risk_level': self.get_risk_level(),
            'findings_count': len(self.findings),
            'findings': self.findings[:50],  # Limit to 50 for readability
            'summary': {
                'suspicious_processes': len(self.suspicious_processes),
                'suspicious_files': len(self.suspicious_files),
                'suspicious_connections': len(self.suspicious_connections)
            }
        }

        with open('reports/report.json', 'w') as f:
            json.dump(report, f, indent=2)

        print("\n" + "=" * 50)
        print("[REPORT] Keylogger Detection")
        print("=" * 50)
        print(f"  Risk Score: {report['score']}/100")
        print(f"  Risk Level: {report['risk_level']}")
        print(f"  Total Findings: {len(self.findings)}")
        print(f"    Processes: {len(self.suspicious_processes)}")
        print(f"    Files: {len(self.suspicious_files)}")
        print(f"    Connections: {len(self.suspicious_connections)}")

        if self.findings:
            print("\n  Top Findings:")
            for finding in self.findings[:5]:
                print(f"    [{finding['severity']}] {finding['message']}")

        print(f"\n[REPORT] Saved: reports/report.json")

    def get_risk_level(self):
        """Determine the overall risk level based on the score."""
        if self.score >= 70:
            return 'CRITICAL'
        elif self.score >= 50:
            return 'HIGH'
        elif self.score >= 30:
            return 'MEDIUM'
        elif self.score >= 10:
            return 'LOW'
        else:
            return 'SAFE'

    def run_scan(self):
        """Run all scanning modules."""
        print("""
========================================
  Keylogger Detector
========================================
  Scanning for keyloggers and spyware
========================================
        """)

        self.scan_processes()
        self.scan_files()
        self.check_network_connections()
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(description="Keylogger Detector")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    detector = KeyloggerDetector()
    detector.run_scan()


if __name__ == "__main__":
    main()