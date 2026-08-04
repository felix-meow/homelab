#!/usr/bin/env python3
"""
Password Cracker - Robert Mircea
Homelab Project

Multi-method password hash cracker supporting dictionary, brute-force, and hybrid attacks.
"""

import hashlib
import argparse
import time
import json
import os
from datetime import datetime
import string


class PasswordCracker:
    """Password hash cracker with multiple attack methods."""

    def __init__(self):
        self.found = {}
        self.attempts = 0
        self.start_time = None

    def hash_password(self, password, algorithm='md5'):
        """Calculate hash of a password using the specified algorithm."""
        if algorithm == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def dictionary_attack(self, target_hash, wordlist_file, algorithm='md5'):
        """Attack using a wordlist of common passwords."""
        print(f"[ATTACK] Dictionary attack with: {wordlist_file}")

        if not os.path.exists(wordlist_file):
            print(f"[ERROR] Wordlist not found: {wordlist_file}")
            return None

        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for word in f:
                word = word.strip()
                self.attempts += 1

                hash_value = self.hash_password(word, algorithm)
                if hash_value == target_hash:
                    print(f"[FOUND] Password: {word}")
                    print(f"[STATS] Attempts: {self.attempts}")
                    return word

                if self.attempts % 1000 == 0:
                    print(f"[PROGRESS] Attempts: {self.attempts}, Current: {word[:20]}...")

        print(f"[FAILED] Password not found in dictionary")
        return None

    def brute_force_attack(self, target_hash, max_length=4, chars=None, algorithm='md5'):
        """Attack by trying all possible character combinations."""
        if chars is None:
            chars = string.ascii_lowercase + string.digits

        print(f"[ATTACK] Brute-force (max length: {max_length})")
        print(f"[ATTACK] Character set: {chars[:20]}...")

        return self._bruteforce_recursive('', target_hash, max_length, chars, algorithm)

    def _bruteforce_recursive(self, current, target_hash, max_length, chars, algorithm):
        """Recursive function for brute-force attack."""
        if len(current) > max_length:
            return None

        if current:
            self.attempts += 1
            hash_value = self.hash_password(current, algorithm)

            if hash_value == target_hash:
                print(f"[FOUND] Password: {current}")
                print(f"[STATS] Attempts: {self.attempts}")
                return current

        for c in chars:
            result = self._bruteforce_recursive(current + c, target_hash, max_length, chars, algorithm)
            if result:
                return result

        return None

    def hybrid_attack(self, target_hash, wordlist_file, append_chars='123', algorithm='md5'):
        """Attack by combining dictionary words with suffixes."""
        print(f"[ATTACK] Hybrid attack with: {wordlist_file}")

        if not os.path.exists(wordlist_file):
            print(f"[ERROR] Wordlist not found: {wordlist_file}")
            return None

        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for word in f:
                word = word.strip()

                for suffix in append_chars:
                    test_word = word + suffix
                    self.attempts += 1
                    hash_value = self.hash_password(test_word, algorithm)

                    if hash_value == target_hash:
                        print(f"[FOUND] Password: {test_word}")
                        print(f"[STATS] Attempts: {self.attempts}")
                        return test_word

        print(f"[FAILED] Password not found in hybrid attack")
        return None

    def crack(self, target_hash, method='dictionary', algorithm='md5',
              wordlist='wordlists/common.txt', max_length=4, chars=None):
        """Main cracking function."""
        self.start_time = time.time()

        print("=" * 50)
        print("[CRACK] Password Cracker")
        print("=" * 50)
        print(f"  Target hash: {target_hash}")
        print(f"  Algorithm: {algorithm}")
        print(f"  Method: {method}")
        print("=" * 50 + "\n")

        result = None

        if method == 'dictionary':
            result = self.dictionary_attack(target_hash, wordlist, algorithm)
        elif method == 'bruteforce':
            result = self.brute_force_attack(target_hash, max_length, chars, algorithm)
        elif method == 'hybrid':
            result = self.hybrid_attack(target_hash, wordlist, algorithm)
        else:
            print(f"[ERROR] Unknown method: {method}")

        elapsed = time.time() - self.start_time
        print(f"\n[STATS] Total attempts: {self.attempts}")
        print(f"[STATS] Time elapsed: {elapsed:.2f}s")

        if result:
            print(f"[SUCCESS] Password found: {result}")
        else:
            print(f"[FAILED] Password not found")

        self._generate_report(target_hash, result, algorithm, method, elapsed)
        return result

    def _generate_report(self, target_hash, result, algorithm, method, elapsed):
        """Generate a JSON report of the cracking attempt."""
        os.makedirs('reports', exist_ok=True)

        report = {
            'timestamp': datetime.now().isoformat(),
            'target_hash': target_hash,
            'algorithm': algorithm,
            'method': method,
            'result': result,
            'attempts': self.attempts,
            'time_elapsed': round(elapsed, 2)
        }

        with open('reports/report.json', 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[REPORT] Saved: reports/report.json")


def main():
    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument("-t", "--target", required=True, help="Target hash")
    parser.add_argument("-a", "--algorithm", default="md5",
                       choices=['md5', 'sha1', 'sha256', 'sha512'],
                       help="Hash algorithm (default: md5)")
    parser.add_argument("-m", "--method", default="dictionary",
                       choices=['dictionary', 'bruteforce', 'hybrid'],
                       help="Attack method (default: dictionary)")
    parser.add_argument("-w", "--wordlist", default="wordlists/common.txt",
                       help="Wordlist file path")
    parser.add_argument("-l", "--max-length", type=int, default=4,
                       help="Max length for brute-force (default: 4)")

    args = parser.parse_args()

    cracker = PasswordCracker()
    cracker.crack(
        target_hash=args.target,
        method=args.method,
        algorithm=args.algorithm,
        wordlist=args.wordlist,
        max_length=args.max_length
    )


if __name__ == "__main__":
    main()