#!/usr/bin/env python3
"""
Password Cracker - Robert Mircea
Homelab Project

Multi-method password hash cracker supporting dictionary, brute-force, hybrid,
and rule-based attacks, with salted-hash support and automatic hash-type detection.
"""

import hashlib
import argparse
import time
import json
import os
from datetime import datetime
import string

# Hex-digest length -> algorithm, used for automatic hash-type detection.
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# Leet-speak substitutions applied by the rule-based engine.
LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}


def detect_algorithm(target_hash):
    """Guess the hash algorithm from the digest length. Returns name or None."""
    return HASH_LENGTHS.get(len(target_hash.strip()))


def apply_rules(word):
    """
    Generate hashcat-style mutations of a base word (best-effort subset).

    Rules: original, capitalize, upper, reverse, leet, append common
    suffixes, and toggle-first-letter-plus-suffix combinations.
    """
    variants = set()
    base = [word, word.capitalize(), word.upper(), word.lower(), word[::-1]]

    # Leet substitution on the lowercase form.
    leet = "".join(LEET_MAP.get(c, c) for c in word.lower())
    base.append(leet)

    suffixes = ["", "1", "12", "123", "1234", "!", "@", "2024", "2025", "01"]
    for candidate in base:
        for suffix in suffixes:
            variants.add(candidate + suffix)
    return variants


class PasswordCracker:
    """Password hash cracker with multiple attack methods."""

    def __init__(self, salt="", salt_position="suffix"):
        self.found = {}
        self.attempts = 0
        self.start_time = None
        self.salt = salt
        self.salt_position = salt_position

    def hash_password(self, password, algorithm="md5"):
        """Calculate hash of a password (with optional salt) using the algorithm."""
        if self.salt:
            if self.salt_position == "prefix":
                password = self.salt + password
            else:
                password = password + self.salt

        if algorithm not in ("md5", "sha1", "sha256", "sha512"):
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        return hashlib.new(algorithm, password.encode()).hexdigest()

    def dictionary_attack(self, target_hash, wordlist_file, algorithm="md5"):
        """Attack using a wordlist of common passwords."""
        print(f"[ATTACK] Dictionary attack with: {wordlist_file}")

        if not os.path.exists(wordlist_file):
            print(f"[ERROR] Wordlist not found: {wordlist_file}")
            return None

        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            for word in f:
                word = word.strip()
                self.attempts += 1

                if self.hash_password(word, algorithm) == target_hash:
                    print(f"[FOUND] Password: {word}")
                    print(f"[STATS] Attempts: {self.attempts}")
                    return word

                if self.attempts % 1000 == 0:
                    print(f"[PROGRESS] Attempts: {self.attempts}, Current: {word[:20]}...")

        print("[FAILED] Password not found in dictionary")
        return None

    def rule_based_attack(self, target_hash, wordlist_file, algorithm="md5"):
        """Attack by applying hashcat-style mutation rules to each dictionary word."""
        print(f"[ATTACK] Rule-based attack with: {wordlist_file}")

        if not os.path.exists(wordlist_file):
            print(f"[ERROR] Wordlist not found: {wordlist_file}")
            return None

        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            for word in f:
                word = word.strip()
                if not word:
                    continue
                for candidate in apply_rules(word):
                    self.attempts += 1
                    if self.hash_password(candidate, algorithm) == target_hash:
                        print(f"[FOUND] Password: {candidate} (rule of '{word}')")
                        print(f"[STATS] Attempts: {self.attempts}")
                        return candidate

                    if self.attempts % 5000 == 0:
                        print(f"[PROGRESS] Attempts: {self.attempts}, Base: {word[:20]}...")

        print("[FAILED] Password not found with rules")
        return None

    def brute_force_attack(self, target_hash, max_length=4, chars=None, algorithm="md5"):
        """Attack by trying all possible character combinations."""
        if chars is None:
            chars = string.ascii_lowercase + string.digits

        print(f"[ATTACK] Brute-force (max length: {max_length})")
        print(f"[ATTACK] Character set: {chars[:20]}...")

        return self._bruteforce_recursive("", target_hash, max_length, chars, algorithm)

    def _bruteforce_recursive(self, current, target_hash, max_length, chars, algorithm):
        """Recursive helper for brute-force attack."""
        if len(current) > max_length:
            return None

        if current:
            self.attempts += 1
            if self.hash_password(current, algorithm) == target_hash:
                print(f"[FOUND] Password: {current}")
                print(f"[STATS] Attempts: {self.attempts}")
                return current

        for c in chars:
            result = self._bruteforce_recursive(current + c, target_hash, max_length, chars, algorithm)
            if result:
                return result
        return None

    def hybrid_attack(self, target_hash, wordlist_file, append_chars="123", algorithm="md5"):
        """Attack by combining dictionary words with suffixes."""
        print(f"[ATTACK] Hybrid attack with: {wordlist_file}")

        if not os.path.exists(wordlist_file):
            print(f"[ERROR] Wordlist not found: {wordlist_file}")
            return None

        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            for word in f:
                word = word.strip()
                for suffix in append_chars:
                    test_word = word + suffix
                    self.attempts += 1
                    if self.hash_password(test_word, algorithm) == target_hash:
                        print(f"[FOUND] Password: {test_word}")
                        print(f"[STATS] Attempts: {self.attempts}")
                        return test_word

        print("[FAILED] Password not found in hybrid attack")
        return None

    def crack(self, target_hash, method="dictionary", algorithm="md5",
              wordlist="wordlists/common.txt", max_length=4, chars=None):
        """Main cracking function."""
        self.start_time = time.time()

        # Automatic hash-type detection.
        if algorithm == "auto":
            detected = detect_algorithm(target_hash)
            if detected is None:
                print(f"[ERROR] Could not auto-detect algorithm for hash length {len(target_hash)}")
                return None
            algorithm = detected
            print(f"[AUTO] Detected algorithm: {algorithm}")

        print("=" * 50)
        print("[CRACK] Password Cracker")
        print("=" * 50)
        print(f"  Target hash: {target_hash}")
        print(f"  Algorithm: {algorithm}")
        print(f"  Method: {method}")
        if self.salt:
            print(f"  Salt: '{self.salt}' ({self.salt_position})")
        print("=" * 50 + "\n")

        result = None
        if method == "dictionary":
            result = self.dictionary_attack(target_hash, wordlist, algorithm)
        elif method == "bruteforce":
            result = self.brute_force_attack(target_hash, max_length, chars, algorithm)
        elif method == "hybrid":
            result = self.hybrid_attack(target_hash, wordlist, algorithm)
        elif method == "rules":
            result = self.rule_based_attack(target_hash, wordlist, algorithm)
        else:
            print(f"[ERROR] Unknown method: {method}")

        elapsed = time.time() - self.start_time
        print(f"\n[STATS] Total attempts: {self.attempts}")
        print(f"[STATS] Time elapsed: {elapsed:.2f}s")

        if result:
            print(f"[SUCCESS] Password found: {result}")
        else:
            print("[FAILED] Password not found")

        self._generate_report(target_hash, result, algorithm, method, elapsed)
        return result

    def _generate_report(self, target_hash, result, algorithm, method, elapsed):
        """Generate a JSON report of the cracking attempt."""
        _rep = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(_rep, exist_ok=True)

        report = {
            "timestamp": datetime.now().isoformat(),
            "target_hash": target_hash,
            "algorithm": algorithm,
            "method": method,
            "salt": self.salt or None,
            "salt_position": self.salt_position if self.salt else None,
            "result": result,
            "attempts": self.attempts,
            "time_elapsed": round(elapsed, 2),
        }

        with open(os.path.join(_rep, "report.json"), "w") as f:
            json.dump(report, f, indent=2)

        print("\n[REPORT] Saved: reports/report.json")


def main():
    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument("-t", "--target", required=True, help="Target hash")
    parser.add_argument("-a", "--algorithm", default="md5",
                        choices=["auto", "md5", "sha1", "sha256", "sha512"],
                        help="Hash algorithm, or 'auto' to detect (default: md5)")
    parser.add_argument("-m", "--method", default="dictionary",
                        choices=["dictionary", "bruteforce", "hybrid", "rules"],
                        help="Attack method (default: dictionary)")
    parser.add_argument("-w", "--wordlist", default="wordlists/common.txt",
                        help="Wordlist file path")
    parser.add_argument("-l", "--max-length", type=int, default=4,
                        help="Max length for brute-force (default: 4)")
    parser.add_argument("--salt", default="", help="Salt value for salted hashes")
    parser.add_argument("--salt-position", choices=["prefix", "suffix"], default="suffix",
                        help="Where the salt is applied (default: suffix)")

    args = parser.parse_args()

    cracker = PasswordCracker(salt=args.salt, salt_position=args.salt_position)
    cracker.crack(
        target_hash=args.target,
        method=args.method,
        algorithm=args.algorithm,
        wordlist=args.wordlist,
        max_length=args.max_length,
    )


if __name__ == "__main__":
    main()
