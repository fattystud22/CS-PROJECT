# phishing_detector.py
import re
from urllib.parse import urlparse, parse_qs

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".top", ".click", ".link", ".work", ".party"
]

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "account", "verify", "verification",
    "secure", "update", "confirm", "banking", "paypal", "amazon", "apple",
    "microsoft", "google", "facebook", "instagram", "netflix", "wellsfargo",
    "bankofamerica", "chase", "citibank", "password", "credential", "wallet",
]

POPULAR_DOMAINS = [
    "paypal", "amazon", "google", "facebook", "apple",
    "microsoft", "netflix", "instagram", "twitter", "linkedin"
]

def analyze_url(raw_url: str) -> dict:
    # Prepend http:// if missing so urlparse works
    if not raw_url.startswith("http"):
        raw_url = "http://" + raw_url

    try:
        parsed = urlparse(raw_url)
        hostname = parsed.hostname.lower()
        pathname = parsed.path.lower()
        query_params = parse_qs(parsed.query)
    except Exception:
        return {
            "riskScore": 80,
            "verdict": "phishing",
            "indicators": [{
                "name": "Invalid URL",
                "description": "The URL could not be parsed.",
                "severity": "high",
                "triggered": True
            }]
        }

    indicators = []
    domain_part = re.sub(r"^www\.", "", hostname)

    # 1. HTTPS check
    indicators.append({
        "name": "No HTTPS",
        "description": "URL does not use a secure HTTPS connection.",
        "severity": "medium",
        "triggered": parsed.scheme != "https"
    })

    # 2. IP address as hostname
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    indicators.append({
        "name": "IP Address as Host",
        "description": "Uses a raw IP address — a common phishing tactic.",
        "severity": "high",
        "triggered": is_ip
    })

    # 3. Suspicious TLD
    has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    indicators.append({
        "name": "Suspicious TLD",
        "description": "TLD commonly used in disposable/phishing domains.",
        "severity": "medium",
        "triggered": has_suspicious_tld
    })

    # 4. Phishing keyword in domain
    has_keyword = any(kw in domain_part for kw in PHISHING_KEYWORDS)
    indicators.append({
        "name": "Brand/Phishing Keyword in Domain",
        "description": "Domain contains a known brand or phishing keyword.",
        "severity": "high",
        "triggered": has_keyword
    })

    # 5. @ symbol in URL (redirect trick)
    indicators.append({
        "name": "@ Symbol in URL",
        "description": "@ in URL can redirect to a different host than shown.",
        "severity": "high",
        "triggered": "@" in raw_url
    })

    # 6. Excessive subdomains
    subdomain_count = len(hostname.split(".")) - 2
    indicators.append({
        "name": "Excessive Subdomains",
        "description": "Too many subdomains used to fake legitimacy.",
        "severity": "medium",
        "triggered": subdomain_count > 3
    })

    # 7. Unusually long URL
    indicators.append({
        "name": "Unusually Long URL",
        "description": "Long URLs can obscure the true destination.",
        "severity": "low",
        "triggered": len(raw_url) > 100
    })

    # 8. Double dots in domain
    indicators.append({
        "name": "Double Dots in Domain",
        "description": "Consecutive dots in the domain are abnormal.",
        "severity": "medium",
        "triggered": ".." in hostname
    })

    # 9. Excessive hyphens
    hyphen_count = hostname.count("-")
    indicators.append({
        "name": "Excessive Hyphens in Domain",
        "description": "Many hyphens used to mimic real URLs (e.g. secure-paypal-login.com).",
        "severity": "medium",
        "triggered": hyphen_count >= 3
    })

    # 10. Suspicious path keywords
    path_keywords = ["login", "signin", "verify", "confirm", "account",
                     "password", "update", "secure", "banking"]
    indicators.append({
        "name": "Suspicious Path Keywords",
        "description": "Path contains keywords like login, verify, confirm.",
        "severity": "low",
        "triggered": any(kw in pathname for kw in path_keywords)
    })

    # 11. Redirect parameters
    redirect_params = {"redirect", "url", "goto", "next", "return"}
    indicators.append({
        "name": "Redirect Parameter",
        "description": "URL contains redirect= or next= — may forward to malicious site.",
        "severity": "medium",
        "triggered": bool(redirect_params & set(query_params.keys()))
    })

    # 12. Typosquatting (character substitutions: o→0, a→4, i→1, e→3)
    def has_typosquat(brand):
        if brand in domain_part:
            return False  # already caught by keyword check
        return (
            brand.replace("a", "4") in domain_part or
            brand.replace("o", "0") in domain_part or
            brand.replace("i", "1") in domain_part or
            brand.replace("e", "3") in domain_part
        )

    indicators.append({
        "name": "Possible Typosquatting",
        "description": "Character substitutions detected (e.g. amaz0n, payp4l).",
        "severity": "high",
        "triggered": any(has_typosquat(brand) for brand in POPULAR_DOMAINS)
    })

    # ── Scoring ──────────────────────────────────────────────
    weights = {"high": 25, "medium": 12, "low": 6}
    raw_score = sum(
        weights[ind["severity"]]
        for ind in indicators if ind["triggered"]
    )
    risk_score = min(100, raw_score)

    if risk_score >= 50:
        verdict = "phishing"
    elif risk_score >= 20:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "riskScore": risk_score,
        "verdict": verdict,
        "indicators": indicators
    }


# ── Example usage ─────────────────────────────────────────────
if __name__ == "__main__":
    urls = [
        "http://paypal-secure-login.xyz/verify?redirect=evil.com",
        "https://www.google.com",
        "http://192.168.1.1/admin/login.php",
        "https://amaz0n-account-verify.tk/signin?next=/",
    ]
    for url in urls:
        result = analyze_url(url)
        print(f"\nURL: {url}")
        print(f"  Verdict : {result['verdict'].upper()}")
        print(f"  Score   : {result['riskScore']}/100")
        triggered = [i["name"] for i in result["indicators"] if i["triggered"]]
        print(f"  Flags   : {', '.join(triggered) if triggered else 'None'}")
