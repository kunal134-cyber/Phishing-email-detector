"""
Flask Backend Application for Phishing Email Detector.
Integrates Machine Learning, URL Security Analysis, Email Header Verification,
and Scan History Logging into a cybersecurity dashboard.
"""

import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
import joblib

from email_preprocessor import (
    clean_email_text,
    extract_linguistic_indicators,
    prepare_full_text
)
from url_analyzer import analyze_all_urls
from header_analyzer import analyze_email_headers
from database import init_db, save_scan_result, get_recent_scans, clear_history

# Load environment variables
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_FILE = os.path.join(MODELS_DIR, "phishing_model.joblib")
VECTORIZER_FILE = os.path.join(MODELS_DIR, "tfidf_vectorizer.joblib")
METRICS_FILE = os.path.join(MODELS_DIR, "metrics.json")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "cybersec-default-dev-key")
# 2MB request payload size limit for safety
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# Global model cache
model = None
vectorizer = None
metrics_data = {}


def load_ml_artifacts():
    """Load pre-trained model, TF-IDF vectorizer, and evaluation metrics."""
    global model, vectorizer, metrics_data

    if os.path.exists(MODEL_FILE) and os.path.exists(VECTORIZER_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            vectorizer = joblib.load(VECTORIZER_FILE)
            print("[+] Successfully loaded trained ML model and TF-IDF vectorizer.")
        except Exception as e:
            print(f"[-] Error loading ML model: {e}")
            model = None
            vectorizer = None
    else:
        print("[!] Warning: Model artifacts not found. Run train_model.py to generate them.")

    if os.path.exists(METRICS_FILE):
        try:
            with open(METRICS_FILE, "r", encoding="utf-8") as f:
                metrics_data = json.load(f)
        except Exception as e:
            print(f"[-] Error reading metrics: {e}")
            metrics_data = {}


# Initialize database and load models on startup
init_db()
load_ml_artifacts()


def evaluate_composite_risk(
    ml_prob: float,
    url_results: dict,
    header_results: dict,
    linguistic_results: dict
) -> dict:
    """
    Computes a weighted, multi-layered risk evaluation:
    - ML probability (50% base weight)
    - URL heuristics (30% weight)
    - Header authenticity & spoofing checks (15% weight)
    - Linguistic urgency triggers (5% weight)
    
    Generates actionable recommendations and security indicator explanations.
    """
    url_score = url_results.get("overall_url_risk_score", 0)
    header_score = header_results.get("header_risk_score", 0)
    ling_score = linguistic_results.get("linguistic_risk_score", 0)

    # Base formula combining weighted scores
    composite = (ml_prob * 50.0) + (url_score * 0.30) + (header_score * 0.15) + (ling_score * 0.05)

    # Security rule escalations: If an IP URL, brand impersonation, or SPF/DKIM fail is detected,
    # the composite score should be elevated to reflect high-threat indicators
    if url_score >= 50 or header_score >= 50:
        composite = max(composite, 65.0)

    composite = min(100.0, max(0.0, composite))

    # Determine classification tier
    if composite >= 65.0 or ml_prob >= 0.70 or url_score >= 60:
        classification = "Phishing"
        risk_level = "High Risk"
        badge_class = "danger"
    elif composite >= 35.0 or ml_prob >= 0.40 or url_score >= 30 or header_score >= 30:
        classification = "Suspicious"
        risk_level = "Medium Risk"
        badge_class = "warning"
    else:
        classification = "Likely Legitimate"
        risk_level = "Low Risk"
        badge_class = "success"

    # Compile actionable security recommendations
    recommendations = []
    if classification == "Phishing":
        recommendations.append("DO NOT click any links, open attachments, or reply to this message.")
        recommendations.append("Report this message immediately to your organization's IT/Security team (SOC).")
        recommendations.append("If you have already entered credentials or passwords, reset them immediately via the official provider portal.")
    elif classification == "Suspicious":
        recommendations.append("Exercise extreme caution before clicking any links or providing information.")
        recommendations.append("Independently verify the sender by calling their known official phone number or visiting their official website.")
        recommendations.append("Examine the sender's actual email address and domain rather than relying solely on the display name.")
    else:
        recommendations.append("The email shows no high-confidence phishing indicators.")
        recommendations.append("Maintain good cybersecurity hygiene: never share passwords or two-factor authentication codes via email.")

    # High-level summary string for history logs
    summary_parts = []
    if ml_prob >= 0.60:
        summary_parts.append(f"ML text model flagged high phishing probability ({ml_prob*100:.1f}%)")
    if url_results.get("suspicious_url_count", 0) > 0:
        summary_parts.append(f"{url_results['suspicious_url_count']} suspicious URL(s) detected")
    if header_results.get("reply_to_mismatch"):
        summary_parts.append("Sender & Reply-To mismatch detected")
    if header_results.get("display_name_spoofed"):
        summary_parts.append("Possible display name spoofing")
    if not summary_parts:
        summary_parts.append("No critical indicators detected")

    return {
        "classification": classification,
        "risk_level": risk_level,
        "badge_class": badge_class,
        "composite_score": round(composite, 1),
        "recommendations": recommendations,
        "summary": "; ".join(summary_parts)
    }


@app.route("/")
def index():
    """Renders the main dashboard interface."""
    recent_scans = get_recent_scans(limit=10)
    return render_template(
        "index.html",
        recent_scans=recent_scans,
        metrics=metrics_data,
        model_ready=(model is not None and vectorizer is not None)
    )


@app.route("/api/scan", methods=["POST"])
def scan_email():
    """
    Main email analysis endpoint.
    Processes email text, headers, and URLs, returning comprehensive findings.
    """
    data = request.get_json(silent=True) or request.form

    raw_body = data.get("body", "").strip()
    sender = data.get("sender", "").strip()
    subject = data.get("subject", "").strip()
    raw_headers = data.get("headers", "").strip()
    reply_to = data.get("reply_to", "").strip()
    check_threat_intel = str(data.get("check_threat_intel", "false")).lower() in ("true", "1")

    if not raw_body and not subject:
        return jsonify({
            "success": False,
            "error": "Please provide email body text or a subject to analyze."
        }), 400

    # 1. URL Security Analysis
    combined_content_for_urls = f"{subject}\n{raw_body}\n{raw_headers}"
    url_analysis = analyze_all_urls(combined_content_for_urls, check_threat_intel=check_threat_intel)

    # 2. Email Header Analysis
    header_analysis = analyze_email_headers(
        sender=sender,
        subject=subject,
        raw_headers=raw_headers,
        reply_to=reply_to
    )

    # 3. Linguistic NLP Analysis
    linguistic_analysis = extract_linguistic_indicators(subject=subject, body=raw_body)

    # 4. Machine Learning Inference
    ml_probability = 0.0
    ml_prediction_label = 0
    model_name = "None (Model Not Loaded)"

    if model is not None and vectorizer is not None:
        try:
            full_text = prepare_full_text(subject, raw_body, sender)
            vec = vectorizer.transform([full_text])
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(vec)[0]
                # Index 1 corresponds to class 1 (Phishing)
                ml_probability = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                ml_probability = float(model.predict(vec)[0])

            ml_prediction_label = int(ml_probability >= 0.5)
            model_name = metrics_data.get("selected_model", "Trained Classifier")
        except Exception as e:
            print(f"[-] Inference error: {e}")
            ml_probability = 0.0

    # 5. Composite Risk Calculation
    evaluation = evaluate_composite_risk(
        ml_prob=ml_probability,
        url_results=url_analysis,
        header_results=header_analysis,
        linguistic_results=linguistic_analysis
    )

    # 6. Save Scan to SQLite Audit Log
    scan_id = save_scan_result(
        sender=sender,
        subject=subject,
        classification=evaluation["classification"],
        risk_level=evaluation["risk_level"],
        overall_score=evaluation["composite_score"],
        ml_probability=ml_probability,
        url_count=url_analysis["total_urls"],
        suspicious_url_count=url_analysis["suspicious_url_count"],
        header_issues_count=len(header_analysis["findings"]),
        summary=evaluation["summary"]
    )

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "classification": evaluation["classification"],
        "risk_level": evaluation["risk_level"],
        "badge_class": evaluation["badge_class"],
        "composite_score": evaluation["composite_score"],
        "machine_learning": {
            "model_name": model_name,
            "phishing_probability": round(ml_probability * 100, 2),
            "predicted_class": "Phishing" if ml_prediction_label == 1 else "Legitimate"
        },
        "url_analysis": url_analysis,
        "header_analysis": header_analysis,
        "linguistic_analysis": linguistic_analysis,
        "recommendations": evaluation["recommendations"],
        "disclaimer": (
            "Notice: This prediction is generated by machine learning heuristics and passive security checks. "
            "It serves as an analytical aid and does not constitute a guaranteed determination."
        )
    })


@app.route("/api/history", methods=["GET"])
def get_history():
    """Retrieves recent scan records from SQLite."""
    limit = request.args.get("limit", 25, type=int)
    history = get_recent_scans(limit=limit)
    return jsonify({"success": True, "scans": history})


@app.route("/api/clear-history", methods=["POST"])
def clear_scan_history():
    """Clears all records from scan history."""
    clear_history()
    return jsonify({"success": True, "message": "Scan history cleared successfully."})


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """Returns saved model training evaluation metrics."""
    return jsonify({"success": True, "metrics": metrics_data})


@app.route("/api/samples", methods=["GET"])
def get_sample_emails():
    """Returns preset email samples for quick UI demonstration."""
    samples = {
        "phishing_credential": {
            "sender": "Security Team <security-alert@paypal-account-verify.xyz>",
            "reply_to": "collector@hacker-server.top",
            "subject": "URGENT: Your PayPal Account Has Been Suspended",
            "headers": (
                "From: Security Team <security-alert@paypal-account-verify.xyz>\n"
                "Reply-To: collector@hacker-server.top\n"
                "Subject: URGENT: Your PayPal Account Has Been Suspended\n"
                "Authentication-Results: spf=fail smtp.mailfrom=paypal-account-verify.xyz; dkim=fail; dmarc=fail\n"
                "Received-SPF: Fail\n"
                "Date: Wed, 28 Oct 2026 14:20:00 +0000"
            ),
            "body": (
                "Dear Valued Customer,\n\n"
                "We detected unauthorized login attempts from an unknown device in Moscow, Russia.\n"
                "Your account access has been temporarily restricted to safeguard your financial data.\n\n"
                "You must verify your identity immediately within 12 hours or your funds will be frozen:\n"
                "http://192.168.1.105/paypal/verify_identity?redirect=login.php\n\n"
                "Thank you,\n"
                "PayPal Security Department"
            )
        },
        "spear_phishing_ceo": {
            "sender": "Dr. Arthur Pendelton <ceo-office@company-exec-portal.sbs>",
            "reply_to": "arthur.private8421@gmail.com",
            "subject": "Confidential Request - Wire Transfer Approval Required",
            "headers": (
                "From: Dr. Arthur Pendelton <ceo-office@company-exec-portal.sbs>\n"
                "Reply-To: arthur.private8421@gmail.com\n"
                "Subject: Confidential Request - Wire Transfer Approval Required\n"
                "Authentication-Results: spf=softfail; dkim=none; dmarc=none\n"
                "Date: Wed, 28 Oct 2026 11:15:00 +0000"
            ),
            "body": (
                "Hi,\n\n"
                "I am currently in an urgent board meeting and unable to take incoming telephone calls.\n"
                "We need to execute an emergency wire transfer of $14,500 to secure an acquisition deposit.\n\n"
                "Please review the attached invoice portal immediately: http://executive-wire-portal.top/invoice\n\n"
                "Keep this strictly confidential until the public announcement.\n\n"
                "Best,\nArthur Pendelton\nChief Executive Officer"
            )
        },
        "legitimate_meeting": {
            "sender": "Alex Mercer <alex.mercer@cyberdefense-lab.edu>",
            "reply_to": "alex.mercer@cyberdefense-lab.edu",
            "subject": "Agenda for Thursday Cyber Security Research Sync",
            "headers": (
                "From: Alex Mercer <alex.mercer@cyberdefense-lab.edu>\n"
                "Reply-To: alex.mercer@cyberdefense-lab.edu\n"
                "Subject: Agenda for Thursday Cyber Security Research Sync\n"
                "Authentication-Results: spf=pass smtp.mailfrom=cyberdefense-lab.edu; dkim=pass; dmarc=pass\n"
                "Received-SPF: Pass\n"
                "Message-ID: <a849204-12948-edu@cyberdefense-lab.edu>\n"
                "Date: Wed, 28 Oct 2026 09:30:00 +0000"
            ),
            "body": (
                "Hi Rahul and Team,\n\n"
                "Here is the finalized agenda for our capstone research sync on Thursday at 2:00 PM:\n"
                "1. Review TF-IDF feature weights and hyperparameter benchmarks\n"
                "2. Discuss heuristic rules for spoofed email headers\n"
                "3. Plan automated integration tests for Flask endpoints\n\n"
                "The meeting will be hosted on Google Meet: https://meet.google.com/abc-defg-hij\n\n"
                "See you all tomorrow!\n\n"
                "Best regards,\nAlex Mercer\nCyber Defense Laboratory"
            )
        }
    }
    return jsonify({"success": True, "samples": samples})


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"success": False, "error": "Email content exceeds 2MB limit."}), 413


@app.errorhandler(404)
def not_found(error):
    return jsonify({"success": False, "error": "Requested resource was not found."}), 404


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"success": False, "error": "An internal server error occurred."}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"[*] Starting Phishing Email Detector on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
