# Password Cracker

A multi-method password hash cracker supporting dictionary, brute-force, and hybrid attacks.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates:

- Hash algorithms (MD5, SHA1, SHA256, SHA512)
- Dictionary attacks
- Brute-force attacks
- Hybrid attacks
- Performance optimization

## Technologies

- Python 3.14+
- hashlib
- threading
- argparse

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/password-cracker

pip install -r requirements.txt

## Usage

python3 cracker.py -t <HASH> -a <ALGORITHM> -m <METHOD>

### Options

| Option | Description |
|--------|-------------|
| -t, --target | Target hash (required) |
| -a, --algorithm | Hash algorithm (md5, sha1, sha256, sha512) |
| -m, --method | Attack method (dictionary, bruteforce, hybrid) |
| -w, --wordlist | Wordlist file path |
| -l, --max-length | Max length for brute-force (default: 4) |

### Examples

Dictionary attack:
python3 cracker.py -t 5f4dcc3b5aa765d61d8327deb882cf99 -a md5 -m dictionary

Brute-force attack:
python3 cracker.py -t e2fc714c4727ee9395f324cd2e7f331f -a md5 -m bruteforce -l 4

Hybrid attack:
python3 cracker.py -t 5f4dcc3b5aa765d61d8327deb882cf99 -a md5 -m hybrid

## Example Output

==================================================
[CRACK] Password Cracker
==================================================
  Target hash: 5f4dcc3b5aa765d61d8327deb882cf99
  Algorithm: md5
  Method: dictionary
==================================================

[ATTACK] Dictionary attack with: wordlists/common.txt
[FOUND] Password: password
[STATS] Attempts: 1

[STATS] Total attempts: 1
[STATS] Time elapsed: 0.00s
[SUCCESS] Password found: password

[REPORT] Saved: reports/report.json

## Report Example (JSON)

{
  "timestamp": "2026-08-04T15:00:00.123456",
  "target_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
  "algorithm": "md5",
  "method": "dictionary",
  "result": "password",
  "attempts": 1,
  "time_elapsed": 0.00
}

## Creating a Wordlist

echo "password" > wordlists/common.txt
echo "123456" >> wordlists/common.txt
echo "admin" >> wordlists/common.txt

## Generating Test Hashes

python3 -c "import hashlib; print(hashlib.md5('password'.encode()).hexdigest())"

## Future Improvements

- GPU support (CUDA/OpenCL)
- Rule-based attacks (hashcat-style)
- Salted hash support
- Online wordlist integration
- Automatic hash type detection
- Web interface

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea