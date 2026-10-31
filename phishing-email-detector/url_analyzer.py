"""
URL Security Analysis Module for Phishing Email Detection.
Performs passive/static inspection on extracted URLs without navigating to them.
"""

import os
import re
from urllib.parse import urlparse
import ipaddress
import requests


# Suspicious TLDs commonly abused in automated phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz",
    ".club", ".work", ".click", ".link", ".rest", ".fit", ".surf",
    ".cam", ".icu", ".monster", ".sbs", ".beauty", ".hair"
}

# High-profile brands frequently targeted by spear phishing & credential harvesters
TARGETED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "netflix", "amazon",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "citibank", "dropbox", "docusign", "outlook", "office365", "adobe"
]

# Regex pattern for extracting URLs safely from text/HTML
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)

# Regex pattern to match direct IPv4 / IPv6 addresses
IPV4_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')


def extract_urls(text: str) -> list[str]:
    """
    Safely extract URLs from text or email bodies.
    Normalizes URLs with missing schemes.
    """
    if not text:
        return []
    
    raw_urls = URL_REGEX.findall(text)
    clean_urls = []
    seen = set()

    for u in raw_urls:
        # Strip trailing punctuation often caught in sentences
        cleaned = u.rstrip(".,;!?:)]\"'")
        if cleaned not in seen:
            seen.add(cleaned)
            clean_urls.append(cleaned)

    return clean_urls


def is_ip_address(host: str) -> bool:
    """Check if hostname is a raw IP address (v4 or v6)."""
    if not host:
        return False
    # Strip port if present
    host_clean = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host_clean)
        return True
    except ValueError:
        return False


def check_virustotal_threat_intel(url: str, api_key: str | None = None) -> dict:
    """
    Query VirusTotal v3 API for URL threat intelligence if an API key is configured.
    Falls back gracefully if key is missing or quota exceeded.
    DOES NOT submit or visit the URL; checks cached analysis via base64 identifier.
    """
    key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return {
            "enabled": False,
            "status": "No API key configured (using local heuristic engine)",
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation": 0
        }

    import base64
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {
            "x-apikey": key,
            "Accept": "application/json"
        }
        res = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=4
        )
        if res.status_code == 200:
            data = res.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "enabled": True,
                "status": "Evaluated via VirusTotal",
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "reputation": data.get("reputation", 0)
            }
        elif res.status_code == 404:
            return {
                "enabled": True,
                "status": "URL not found in VirusTotal database (new or unindexed)",
                "malicious_count": 0,
                "suspicious_count": 0,
                "reputation": 0
            }
        else:
            return {
                "enabled": True,
                "status": f"VirusTotal returned status {res.status_code}",
                "malicious_count": 0,
                "suspicious_count": 0,
                "reputation": 0
            }
    except Exception as e:
        return {
            "enabled": True,
            "status": f"Threat intel query error: {str(e)}",
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation": 0
        }


def analyze_single_url(url: str, check_vt: bool = False) -> dict:
    """
    Perform deep static security analysis on an individual URL.
    Returns findings, risk score, and detailed flags.
    """
    flags = []
    risk_score = 0
    
    # Prepend scheme for proper urlparse if missing
    parsed_target = url
    if not url.startswith(("http://", "https://")):
        parsed_target = "http://" + url

    try:
        parsed = urlparse(parsed_target)
    except Exception:
        return {
            "url": url,
            "is_valid": False,
            "risk_score": 50,
            "flags": ["Malformed URL syntax"]
        }

    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else ""

    # 1. IP address in hostname (High risk)
    if is_ip_address(hostname):
        flags.append("Host is a raw IP address instead of domain name")
        risk_score += 40

    # 2. "@" in URL (Credential confusion/redirect trick)
    if "@" in parsed_target:
        flags.append("Contains '@' symbol (URL obfuscation/credential confusion)")
        risk_score += 35

    # 3. Excessive URL length
    if len(url) > 100:
        flags.append(f"Excessive URL length ({len(url)} chars, common in tracking/exploit links)")
        risk_score += 15

    # 4. Excessive subdomains
    if hostname:
        subdomain_parts = hostname.split(".")
        # If parts > 3 (excluding common suffixes like co.uk)
        if len(subdomain_parts) >= 4 and not is_ip_address(hostname):
            flags.append(f"Unusually deep subdomain hierarchy ({len(subdomain_parts)-1} levels)")
            risk_score += 20

    # 5. Suspicious TLD check
    if hostname:
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                flags.append(f"Uses high-abuse top-level domain ({tld})")
                risk_score += 25
                break

    # 6. Brand Impersonation / Typosquatting in hostname
    for brand in TARGETED_BRANDS:
        if brand in hostname:
            # Check if it is the legitimate official domain
            # e.g., paypal.com, login.microsoft.com, support.google.com
            is_legit_domain = False
            legit_suffixes = (f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.co.uk")
            if hostname == brand + ".com" or hostname.endswith("." + brand + ".com") or any(hostname.endswith(sfx) for sfx in legit_suffixes):
                is_legit_domain = True

            if not is_legit_domain:
                flags.append(f"Potential brand impersonation: '{brand}' found in suspicious host '{hostname}'")
                risk_score += 35

    # 7. Open redirect parameters or dangerous keywords in query
    danger_params = ["redirect=", "url=", "goto=", "next=", "target=", "dest=", "return_to="]
    if any(param in query for param in danger_params):
        flags.append("Contains open-redirect parameter in query string")
        risk_score += 20

    # 8. Obfuscated or hexadecimal characters
    if "%" in url:
        hex_encoded = re.findall(r'%[0-9a-fA-F]{2}', url)
        if len(hex_encoded) >= 3:
            flags.append("Multiple hex-encoded (%XX) characters detected (URL obfuscation)")
            risk_score += 15

    # 9. Hyphens in domain (common typosquatting technique)
    if hostname and hostname.count("-") >= 2 and not is_ip_address(hostname):
        flags.append("Domain contains multiple hyphens (common in spoofed domains)")
        risk_score += 15

    # Threat Intelligence check
    threat_intel = {}
    if check_vt:
        threat_intel = check_virustotal_threat_intel(url)
        if threat_intel.get("malicious_count", 0) > 0:
            flags.append(f"VirusTotal detected {threat_intel['malicious_count']} vendor engines flagging this URL")
            risk_score += 50
        elif threat_intel.get("suspicious_count", 0) > 0:
            flags.append(f"VirusTotal detected {threat_intel['suspicious_count']} suspicious vendor flags")
            risk_score += 25

    risk_score = min(100, risk_score)

    return {
        "url": url,
        "hostname": hostname,
        "is_valid": True,
        "risk_score": risk_score,
        "is_suspicious": risk_score >= 30,
        "flags": flags,
        "threat_intel": threat_intel
    }


def analyze_all_urls(text: str, check_threat_intel: bool = False) -> dict:
    """
    Extract and analyze all URLs present in an email body.
    Returns overall URL risk metrics and individual URL breakdown.
    """
    extracted = extract_urls(text)
    if not extracted:
        return {
            "total_urls": 0,
            "has_urls": False,
            "suspicious_url_count": 0,
            "overall_url_risk_score": 0,
            "urls_details": []
        }

    results = [analyze_single_url(u, check_vt=check_threat_intel) for u in extracted]
    suspicious_count = sum(1 for r in results if r["is_suspicious"])
    max_risk = max((r["risk_score"] for r in results), default=0)

    # Calculate blended risk score
    overall_score = min(100, max_risk + (suspicious_count - 1) * 10 if suspicious_count > 1 else max_risk)

    return {
        "total_urls": len(extracted),
        "has_urls": True,
        "suspicious_url_count": suspicious_count,
        "overall_url_risk_score": overall_score,
        "urls_details": results
    }
