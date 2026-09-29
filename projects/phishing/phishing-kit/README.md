# Phishing Kit (test-case generator)

Red-team counterpart of the **phishing-detector**. Generates synthetic phishing
emails as JSON so the detector can be tested and tuned against realistic —
but entirely fake — samples. **This tool sends nothing; it only writes files.**

> Educational / detection-tuning use only. All output is clearly marked as
> synthetic test data (`"generated_by": "phishing-kit (synthetic test data)"`).

## Red vs Blue

| Offensive (this) | Defensive (pair) |
|------------------|------------------|
| phishing-kit — generates phishing samples | phishing-detector — scores and flags them |

## Technologies

- Python 3.14+ (standard library only)

## Usage

```
python3 phishing_kit.py [OPTIONS]
```

| Option | Description |
|--------|-------------|
| -t, --template | Brand template: paypal, bank, delivery, itsupport, random (default: random) |
| -n, --count | Number of emails to generate (default: 1) |
| -o, --output-dir | Directory for JSON samples (default: samples) |
| --obfuscate | Use homoglyph / IDN lookalike domains |
| --clean-auth | Do NOT inject failing SPF/DKIM/DMARC headers |

## Example: generate and detect

```
# Generate a PayPal phishing sample with an IDN-homograph domain
python3 phishing_kit.py -t paypal --obfuscate -o samples

# Feed it to the detector
python3 ../phishing-detector/detector.py -f samples/phish_paypal_*.json
```

The detector should score the sample **100/100 (SUSPICIOUS)**, flagging the
spoofed authentication headers, Reply-To mismatch, homoglyph URL, suspicious
keywords, and urgency language.

## What it models

- Spoofed `From` (brand) with an attacker-controlled `Reply-To`
- Failing SPF/DKIM/DMARC (typical of spoofed senders)
- Lookalike / homoglyph domains and random landing-page paths
- Urgency-driven body content

## Author

Robert Mircea — GitHub: felix-meow
