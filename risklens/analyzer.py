import json 
import re
import hashlib
from pathlib import Path 
from urllib.parse import urlparse 


def _load_config() -> dict:
    """Loads phishing indicators from keywords config file."""
    config_path = Path(__file__).parent/ "config" / "keywords.json"
    with open(config_path, "r") as f:
        return json.load(f)
    

def _is_trusted(domain: str, trusted:list) -> bool:
    """Checks if the domain matches a known trusted domain."""
    return any(domain == t or domain.endswith("." + t) for t in trusted )

def _find_keywords(url: str, keywords: list) -> list:
    """Returns any suspicious keyword found in the URL."""
    return [kw for kw in keywords if kw in url]

def _find_patterns(url: str, patterns:list) -> list:
    """Returns suspicious patterns found in the URL"""
    return [p for p in patterns if p in url]

def _check_tld(domain: str, suspicious_tlds: list) -> bool:
    """Checks if the domain uses a top-level domain."""
    return any(domain.endswith(tld) for tld in suspicious_tlds)

def _is_ip_address(domain: str) -> bool:
    """Checks if the domain is a raw IP address. A common phishing indicator.""" 
    parts = domain.split(".")
    return len(parts) == 4 and all (p.isdigit() for p in parts)

def _count_subdomains(domain:str) -> int:
    """Counts subdomains. Excessive domains are red flag."""
    parts = domain.split(".")
    return max(0, len(parts) - 2)

def analyze_url(url: str) -> dict:
    """
    Parses a URL and extracts features used for phishing detection.
    Returns a dictionary of findings.
    """
    config = _load_config()
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full_url = url.lower()

    findings = {
        "url":url,
        "url_hash": hashlib.sha256(url.encode()).hexdigest(),
        "scheme": parsed.scheme,
        "domain": domain,
        "path": parsed.path, 
        "is_https": parsed.scheme == "https",
        "is_trusted_domain": _is_trusted(domain, config["trusted_domains"]),
        "suspicious_keywords": _find_keywords(full_url, config["suspicious_keywords"]),
        "suspicious_patterns": _find_patterns(full_url, config["suspicious_patterns"]),
        "suspicious_tld": _check_tld(domain, config["suspicious_tlds"]),
        "has_ip_address": _is_ip_address(domain),
        "subdomain_count":_count_subdomains(domain),
        "url_length": len(url),
    }
    return findings


