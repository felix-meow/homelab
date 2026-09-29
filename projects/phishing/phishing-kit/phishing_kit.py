#!/usr/bin/env python3
"""
Phishing Kit (test-case generator) - Robert Mircea
Homelab Project - OFFENSIVE (red-team pair for phishing-detector)

Generates synthetic phishing emails as JSON so the phishing-detector can be
tested and tuned against realistic-but-fake samples. This tool sends nothing;
it only writes files. It is the red-team counterpart of the blue-team
phishing-detector and exists purely for educational / detection-tuning use.
"""

import argparse
import json
import os
import random
import string
from datetime import datetime

# Brand templates: (display name, legit domain, lookalike domain, subject, body).
TEMPLATES = {
    "paypal": {
        "brand": "PayPal",
        "legit": "paypal.com",
        "lookalike": "paypal-secure-verify.tk",
        "from": "service@paypal.com",
        "subject": "Your account has been limited",
        "body": ("Dear customer, we detected unusual activity. You must verify "
                 "your account immediately or it will be suspended. "
                 "Confirm here: {url}"),
    },
    "bank": {
        "brand": "Bank of America",
        "legit": "bankofamerica.com",
        "lookalike": "secure-bofa-login.ga",
        "from": "alerts@bankofamerica.com",
        "subject": "Urgent: unauthorized login attempt",
        "body": ("We blocked a suspicious sign-in to your account. Review the "
                 "activity within 24 hours to avoid a hold: {url}"),
    },
    "delivery": {
        "brand": "DHL",
        "legit": "dhl.com",
        "lookalike": "dhl-parcel-redelivery.xyz",
        "from": "noreply@dhl.com",
        "subject": "Your package could not be delivered",
        "body": ("Your parcel is on hold. Pay the outstanding customs fee to "
                 "schedule redelivery today: {url}"),
    },
    "itsupport": {
        "brand": "IT Helpdesk",
        "legit": "company.com",
        "lookalike": "company-mail-portal.top",
        "from": "helpdesk@company.com",
        "subject": "Action required: mailbox password expires today",
        "body": ("Your email password expires in 2 hours. Re-validate now to "
                 "keep access to your mailbox: {url}"),
    },
}

# Latin -> confusable homoglyph, for optional domain obfuscation.
HOMOGLYPH = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і"}

# Evasive lookalikes: legit .com TLDs, no homoglyph, brand as combosquat/subdomain.
EVASIVE_DOMAINS = {
    "paypal": "paypal.account-support-center.com",
    "bank": "secure.bofa-online-portal.com",
    "delivery": "dhl.parcel-tracking-service.com",
    "itsupport": "mail.company-it-portal.com",
}
# Benign pretext bodies: no urgency, no classic phishing keywords.
BENIGN_BODIES = {
    "paypal": "Hello, your monthly statement is ready. You can view it any time here: {url}. Thank you for being a customer.",
    "bank": "Hi, the document you requested from your relationship manager is available for review here: {url}.",
    "delivery": "Hello, tracking details for your recent order are now available here: {url}. Have a great day.",
    "itsupport": "Hi, the knowledge-base article you asked about is here: {url}. Let us know if it helps.",
}


def homoglyph_domain(domain):
    """Replace a couple of ASCII letters with lookalike Unicode characters."""
    chars = list(domain)
    swappable = [i for i, c in enumerate(chars) if c in HOMOGLYPH]
    for i in random.sample(swappable, min(2, len(swappable))):
        chars[i] = HOMOGLYPH[chars[i]]
    return "".join(chars)


def random_path():
    """Return a random-looking URL path used by phishing landing pages."""
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return random.choice(["/verify", "/login", "/secure", "/account"]) + f"?id={token}"


def build_email(template_name, obfuscate=False, spoof_auth=True, evasive=False):
    """Build a single synthetic phishing email dict."""
    t = TEMPLATES[template_name]

    if evasive:
        # Sophisticated evasion: legit-TLD combosquat domain, HTTPS, benign
        # language, no Reply-To mismatch, passing/clean auth.
        domain = EVASIVE_DOMAINS[template_name]
        url = f"https://{domain}{random_path()}"
        headers = {"from": f"support@{domain}"}
        subject = "Your document is ready"
        body = BENIGN_BODIES[template_name].format(url=url)
        return {
            "generated_by": "phishing-kit (synthetic test data)",
            "template": template_name,
            "subject": subject,
            "body": body,
            "headers": headers,
        }

    domain = t["lookalike"]
    if obfuscate:
        # Use a homoglyph of the *legit* domain to mimic an IDN homograph attack.
        domain = homoglyph_domain(t["legit"])

    url = f"http://{domain}{random_path()}"

    headers = {
        # From is spoofed to look like the real brand; Reply-To leaks the attacker.
        "from": t["from"],
        "reply-to": f"collect@{t['lookalike']}",
    }
    if spoof_auth:
        # Failing authentication is what a spoofed sender typically produces.
        headers["spf"] = "fail"
        headers["dkim"] = "fail"
        headers["dmarc"] = "fail"

    return {
        "generated_by": "phishing-kit (synthetic test data)",
        "template": template_name,
        "subject": t["subject"],
        "body": t["body"].format(url=url),
        "headers": headers,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Phishing test-case generator (pairs with phishing-detector)"
    )
    parser.add_argument("-t", "--template", default="random",
                        choices=list(TEMPLATES) + ["random"],
                        help="Brand template to use (default: random)")
    parser.add_argument("-n", "--count", type=int, default=1,
                        help="Number of emails to generate (default: 1)")
    parser.add_argument("-o", "--output-dir", default="samples",
                        help="Directory to write JSON samples (default: samples)")
    parser.add_argument("--obfuscate", action="store_true",
                        help="Use homoglyph/IDN lookalike domains")
    parser.add_argument("--clean-auth", action="store_true",
                        help="Do NOT inject failing SPF/DKIM/DMARC headers")
    parser.add_argument("--evasive", action="store_true",
                        help="Sophisticated evasion: legit-TLD combosquat, HTTPS, benign language, clean auth")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    print(f"[KIT] Generating {args.count} synthetic phishing sample(s)...")

    for i in range(args.count):
        name = random.choice(list(TEMPLATES)) if args.template == "random" else args.template
        email = build_email(name, obfuscate=args.obfuscate, spoof_auth=not args.clean_auth, evasive=args.evasive)

        stamp = datetime.now().strftime("%H%M%S")
        path = os.path.join(args.output_dir, f"phish_{name}_{stamp}_{i}.json")
        with open(path, "w") as f:
            json.dump(email, f, indent=2, ensure_ascii=False)
        print(f"  [SAMPLE] {name:9} -> {path}")

    print(f"\n[KIT] Done. Test the detector with:")
    print(f"  python3 ../phishing-detector/detector.py -f {args.output_dir}/<file>.json")


if __name__ == "__main__":
    main()
