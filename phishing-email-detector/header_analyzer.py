"""
Email Header Security Analysis Module.
Parses raw email headers, evaluates SPF/DKIM/DMARC authentication,
and detects header spoofing, Reply-To mismatches, and display name deception.
"""

import re
import email
from email import policy
from email.utils import parseaddr


def parse_email_address(raw_address: str) -> tuple[str, str, str]:
    """
    Extract display name, full email, and domain from an address string.
    e.g., 'PayPal Security <security@paypal.com>' -> ('PayPal Security', 'security@paypal.com', 'paypal.com')
    """
    if not raw_address:
        return "", "", ""

    display_name, addr = parseaddr(raw_address.strip())
    domain = ""
    if "@" in addr:
        domain = addr.split("@")[-1].lower().strip()
    return display_name.strip(), addr.lower().strip(), domain


def extract_auth_status(header_text: str, protocol: str) -> str:
    """
    Extract authentication outcome (pass/fail/softfail/neutral/temperror/permerror)
    from Authentication-Results or Received-SPF headers.
    Returns 'Unknown' if the header does not explicitly specify a result.
    """
    if not header_text:
        return "Unknown"

    text = header_text.lower()
    pattern = rf'{protocol}\s*=\s*([a-z]+)'
    match = re.search(pattern, text)
    if match:
        status = match.group(1).capitalize()
        # Common authentication states
        if status.lower() in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
            return status
    
    # Received-SPF specific pattern
    if protocol == "spf":
        spf_direct = re.search(r'^(pass|fail|softfail|neutral|none)', text.strip())
        if spf_direct:
            return spf_direct.group(1).capitalize()

    return "Unknown"


def analyze_email_headers(
    sender: str = "",
    subject: str = "",
    raw_headers: str = "",
    reply_to: str = ""
) -> dict:
    """
    Analyze email metadata and raw headers for signs of spoofing or forgery.
    Leaves absent checks as 'Unknown' rather than inventing false data.
    """
    findings = []
    risk_score = 0
    header_dict = {}

    # Parse raw headers if provided
    if raw_headers and raw_headers.strip():
        try:
            msg = email.message_from_string(raw_headers, policy=policy.default)
            for k, v in msg.items():
                header_dict[k.lower()] = str(v)
        except Exception:
            findings.append("Headers could not be cleanly parsed as standard RFC 822 format")
            risk_score += 10

    # Determine sender information
    effective_from = sender.strip()
    if not effective_from and "from" in header_dict:
        effective_from = header_dict["from"]

    from_name, from_email, from_domain = parse_email_address(effective_from)

    # Determine Reply-To information
    effective_reply_to = reply_to.strip()
    if not effective_reply_to and "reply-to" in header_dict:
        effective_reply_to = header_dict["reply-to"]

    reply_name, reply_email, reply_domain = parse_email_address(effective_reply_to)

    # 1. Sender vs Reply-To Mismatch Analysis
    reply_to_mismatch = False
    if from_domain and reply_domain and from_domain != reply_domain:
        reply_to_mismatch = True
        findings.append(
            f"Sender domain ({from_domain}) does not match Reply-To domain ({reply_domain}). "
            "Replies will be routed to a different domain, a standard phishing tactic."
        )
        risk_score += 35

    # 2. Display Name Spoofing
    # e.g., Display name contains a company domain or email like 'support@paypal.com'
    display_name_spoofed = False
    if from_name:
        # Check if display name includes an email pattern or high-value brand
        if "@" in from_name:
            display_name_spoofed = True
            findings.append(f"Display name '{from_name}' contains an embedded email address to disguise true sender.")
            risk_score += 25
        elif any(brand in from_name.lower() for brand in ["paypal", "microsoft", "google", "apple", "bank", "security"]):
            if from_domain and not any(brand in from_domain for brand in ["paypal", "microsoft", "google", "apple"]):
                display_name_spoofed = True
                findings.append(
                    f"Display name mentions trusted brand '{from_name}' but sending domain is '{from_domain}'."
                )
                risk_score += 30

    # 3. Authentication Verification (SPF, DKIM, DMARC)
    auth_results_header = header_dict.get("authentication-results", "")
    received_spf_header = header_dict.get("received-spf", "")
    dkim_signature_header = header_dict.get("dkim-signature", "")

    spf_status = extract_auth_status(auth_results_header, "spf")
    if spf_status == "Unknown" and received_spf_header:
        spf_status = extract_auth_status(received_spf_header, "spf")

    dkim_status = extract_auth_status(auth_results_header, "dkim")
    if dkim_status == "Unknown" and dkim_signature_header:
        dkim_status = "Present (Unverified without DNS)"

    dmarc_status = extract_auth_status(auth_results_header, "dmarc")

    # Evaluate authentication risk
    if spf_status.lower() in ("fail", "softfail"):
        findings.append(f"SPF authentication {spf_status.upper()}: Sending mail server is not authorized by domain SPF record.")
        risk_score += 30
    elif spf_status.lower() == "pass":
        risk_score = max(0, risk_score - 10)

    if dkim_status.lower() == "fail":
        findings.append("DKIM authentication FAIL: Cryptographic signature is invalid or body was modified in transit.")
        risk_score += 30
    elif dkim_status.lower() == "pass":
        risk_score = max(0, risk_score - 10)

    if dmarc_status.lower() == "fail":
        findings.append("DMARC authentication FAIL: Message failed domain alignment policy.")
        risk_score += 35
    elif dmarc_status.lower() == "pass":
        risk_score = max(0, risk_score - 15)

    # 4. Return-Path vs From mismatch
    return_path = header_dict.get("return-path", "")
    _, _, return_domain = parse_email_address(return_path)
    if return_domain and from_domain and return_domain != from_domain:
        findings.append(f"Return-Path domain ({return_domain}) differs from From domain ({from_domain}).")
        risk_score += 15

    # 5. Missing basic headers
    if raw_headers and raw_headers.strip():
        if "message-id" not in header_dict:
            findings.append("Missing standard 'Message-ID' header.")
            risk_score += 10
        if "date" not in header_dict:
            findings.append("Missing standard 'Date' header.")
            risk_score += 5

    risk_score = max(0, min(100, risk_score))

    return {
        "from_address": from_email,
        "from_domain": from_domain,
        "from_name": from_name,
        "reply_to": reply_email,
        "reply_to_domain": reply_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "display_name_spoofed": display_name_spoofed,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "header_risk_score": risk_score,
        "findings": findings,
        "has_raw_headers": bool(raw_headers.strip())
    }
