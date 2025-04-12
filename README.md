import re
from urllib.parse import urlparse

# List of known good domains (whitelist)
SAFE_DOMAINS = ['google.com', 'paypal.com', 'amazon.com', 'microsoft.com']

# Suspicious keywords commonly found in phishing content
SUSPICIOUS_KEYWORDS = [
    'verify your account',
    'update your password',
    'login to your account',
    'click here to update',
    'unauthorized login attempt',
    'your account has been suspended'
]

# Detects suspicious domain names (like paypa1.com instead of paypal.com)
def is_domain_suspicious(url):
    domain = urlparse(url).netloc.lower()
    for safe in SAFE_DOMAINS:
        if safe in domain and domain != safe:
            print(f"[ALERT] Suspicious variation of domain detected: {domain}")
            return True
    return False

# Scan email or webpage content for phishing keywords
def contains_phishing_keywords(text):
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text.lower():
            print(f"[ALERT] Phishing keyword found: '{keyword}'")
            return True
    return False

# Main phishing protection checker
def phishing_protection_check(url, content):
    alerts = []

    if is_domain_suspicious(url):
        alerts.append("⚠️ Suspicious domain detected.")

    if contains_phishing_keywords(content):
        alerts.append("⚠️ Phishing keywords detected in content.")

    if alerts:
        print("\n".join(alerts))
        print("⚠️ Potential phishing attempt detected. Do not trust this source.")
    else:
        print("✅ No phishing detected. URL and content seem safe.")

# Example Usage
test_url = "http://paypa1.com/login"
test_content = "Please verify your account immediately to avoid suspension."

phishing_protection_check(test_url, test_content)
