"""
Email Text Cleaning and NLP Feature Extraction Module.
Normalizes text, strips extraneous HTML, extracts structural linguistic indicators,
and prepares inputs for TF-IDF vectorization and machine learning classifiers.
"""

import re
import html

# Common urgency and call-to-action triggers frequently observed in phishing attacks
URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate action", "account suspended", "suspended",
    "verify your account", "verify now", "update payment", "security alert",
    "unauthorized access", "unauthorized login", "unusual activity", "limited time",
    "password expired", "compromised", "billing problem", "action required",
    "account closure", "wire transfer", "gift card", "crypto", "tax refund",
    "irs", "final notice", "terminated", "critical update", "validate",
    "click here", "log in below", "confirm your identity", "reset password"
]


def clean_email_text(raw_text: str) -> str:
    """
    Cleans raw email content for NLP processing:
    - Decodes HTML entities
    - Strips HTML tags
    - Replaces URLs with a normalized token
    - Replaces currency amounts with a normalized token
    - Replaces numbers with space
    - Normalizes multiple spaces and lowercases
    """
    if not raw_text or not isinstance(raw_text, str):
        return ""

    # Decode HTML entities (e.g. &amp; -> &)
    text = html.unescape(raw_text)

    # Strip HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)

    # Normalize URLs into special placeholder token
    text = re.sub(r'https?://\S+|www\.\S+', ' __url_token__ ', text)

    # Normalize monetary values (e.g., $5,000, £200, €50)
    text = re.sub(r'[\$\£\€]\s*\d+(?:,\d+)*(?:\.\d+)?', ' __currency_token__ ', text)

    # Replace numbers/digits
    text = re.sub(r'\b\d+\b', ' ', text)

    # Remove non-alphanumeric punctuation except token underscores
    text = re.sub(r'[^\w\s_]', ' ', text)

    # Collapse repeated whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    return text.lower()


def extract_linguistic_indicators(subject: str, body: str) -> dict:
    """
    Extract rule-based NLP indicators from email subject and body:
    - Urgency keyword hits
    - Uppercase ratio (shouting)
    - Exclamation mark count
    - Money/currency mentions
    """
    combined = f"{subject} {body}"
    combined_lower = combined.lower()

    # 1. Detect urgency keywords
    matched_keywords = []
    for kw in URGENCY_KEYWORDS:
        if kw in combined_lower:
            matched_keywords.append(kw)

    # 2. Uppercase ratio (often indicates aggressive urgency)
    total_letters = sum(1 for c in combined if c.isalpha())
    upper_letters = sum(1 for c in combined if c.isupper())
    upper_ratio = (upper_letters / total_letters) if total_letters > 0 else 0.0

    # 3. Exclamation marks
    exclamation_count = combined.count("!")

    # 4. Currency mentions
    currency_count = len(re.findall(r'[\$\£\€]|\b(?:usd|eur|dollars?|inr|crypto|bitcoin)\b', combined_lower))

    # Calculate heuristic linguistic urgency score (0 - 100)
    urgency_score = min(
        100,
        (len(matched_keywords) * 15)
        + (int(upper_ratio > 0.25) * 20)
        + (min(exclamation_count, 5) * 5)
        + (min(currency_count, 3) * 10)
    )

    return {
        "matched_urgency_keywords": matched_keywords,
        "urgency_keyword_count": len(matched_keywords),
        "uppercase_ratio": round(upper_ratio, 3),
        "exclamation_count": exclamation_count,
        "currency_mentions": currency_count,
        "linguistic_risk_score": urgency_score
    }


def prepare_full_text(subject: str, body: str, sender: str = "") -> str:
    """
    Prepares a unified sanitized text string for TF-IDF feature extraction.
    Weighs subject slightly by repeating or prefixing it.
    """
    subject_cleaned = clean_email_text(subject)
    body_cleaned = clean_email_text(body)
    sender_cleaned = clean_email_text(sender)

    # Combine subject (weighted twice) with sender and body
    return f"{sender_cleaned} {subject_cleaned} {subject_cleaned} {body_cleaned}".strip()
