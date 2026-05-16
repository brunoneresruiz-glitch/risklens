SIGNALS = {
    "no_https": {
        "severity": "medium",
        "description": "Connection is not encrypted (HTTP instead of HTTPS)",
    },
    "ip_as_domain": {
        "severity": "high",
        "description": "Raw IP address used instead of a domain name",
    },
    "suspicious_tld": {
        "severity": "high",
        "description": "Domain uses a high-risk top-level domain",
    },
    "excessive_subdomains": {
        "severity": "medium",
        "description": "Unusual number of subdomains detected",
    },
    "brand_impersonation": {
        "severity": "high",
        "description": "URL appears to imitate a known trusted brand",
    },
    "suspicious_keywords": {
        "severity": "medium",
        "description": "Phishing-related keywords found in URL",
    },
    "url_obfuscation": {
        "severity": "high",
        "description": "Obfuscation pattern detected (e.g. @ symbol or double slashes)",
    },
    "url_too_long": {
        "severity": "low",
        "description": "URL length is abnormally long",
    },
}


def evaluate(findings: dict) -> dict:
    """
    Evaluates analyzer findings against known phishing signals.
    Returns a verdict and the signals that justify it.
    """
    triggered = []

    if not findings["is_https"]:
        triggered.append("no_https")

    if findings["has_ip_address"]:
        triggered.append("ip_as_domain")

    if findings["suspicious_tld"]:
        triggered.append("suspicious_tld")

    if findings["subdomain_count"] > 2:
        triggered.append("excessive_subdomains")

    if findings["url_length"] > 75:
        triggered.append("url_too_long")

    if findings["suspicious_keywords"]:
        triggered.append("suspicious_keywords")

    if findings["suspicious_patterns"]:
        triggered.append("url_obfuscation")

    if _is_brand_impersonation(findings):
        triggered.append("brand_impersonation")

    verdict = _get_verdict(triggered)

    return {
        "verdict": verdict,
        "signals": [
            {
                "id": signal_id,
                "severity": SIGNALS[signal_id]["severity"],
                "description": SIGNALS[signal_id]["description"],
            }
            for signal_id in triggered
        ],
    }


def _is_brand_impersonation(findings: dict) -> bool:
    """
    Detects if the URL imitates a trusted brand without being that brand's domain.
    """
    trusted_brands = [
        "paypal", "amazon", "apple", "microsoft", "google",
        "netflix", "instagram", "facebook", "linkedin", "dropbox",
        "revolut", "aib", "bankofireland",
    ]
    domain = findings["domain"]
    is_trusted = findings["is_trusted_domain"]

    if is_trusted:
        return False

    return any(brand in domain for brand in trusted_brands)


def _get_verdict(triggered: list) -> str:
    """
    Determines the final verdict based on severity of triggered signals.
    """
    severities = [SIGNALS[s]["severity"] for s in triggered]

    if "high" in severities:
        return "HIGH RISK"
    elif severities.count("medium") >= 2:
        return "MEDIUM RISK"
    elif severities:
        return "LOW RISK"
    else:
        return "SAFE"