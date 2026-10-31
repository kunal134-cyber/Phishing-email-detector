# 🛡️ PhishShield | Multi-Layered AI Phishing & Threat Detection System

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask 3.0+](https://img.shields.io/badge/Framework-Flask_3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Pytest Passed](https://img.shields.io/badge/Tests-19%2F19%20Passed-10b981?style=for-the-badge&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![Cybersecurity Portfolio](https://img.shields.io/badge/Domain-B.Tech_Cyber_Security-2563eb?style=for-the-badge&logo=shield&logoColor=white)](#)

> **PhishShield** is an analytical cybersecurity dashboard that detects sophisticated phishing, spear-phishing, and Business Email Compromise (BEC) attacks. It combines **Natural Language Processing (TF-IDF)**, **Supervised Machine Learning (Logistic Regression vs. Random Forest)**, **Passive URL Threat Heuristics**, and **RFC 822/5322 Email Header Authentication (SPF, DKIM, DMARC)** into a unified composite risk score.

---

## 📑 Table of Contents
- [System Architecture & Threat Pipeline](#-system-architecture--threat-pipeline)
- [Multi-Tier Detection Mechanics](#-multi-tier-detection-mechanics)
- [Machine Learning Benchmark & Results](#-machine-learning-benchmark--results)
- [Dashboard Walkthrough](#-dashboard-walkthrough)
- [Project Directory Structure](#-project-directory-structure)
- [Quick Start Guide](#-quick-start-guide)
  - [Windows (PowerShell)](#windows-powershell)
  - [Kali Linux / Ubuntu](#kali-linux--ubuntu)
- [Sample Threat Vectors (For Demo)](#-sample-threat-vectors-for-demo)
- [Automated Testing](#-automated-testing)
- [Viva Defense & Interview Q&A](#-viva-defense--interview-qa)
- [Security Safeguards](#-security-safeguards)
- [Author & Acknowledgments](#-author--acknowledgments)

---

## 🏛️ System Architecture & Threat Pipeline

The core philosophy of **PhishShield** is **Defense-in-Depth**. Single-layer detectors (such as text-only NLP filters) fail against spear-phishing emails containing polite text and a malicious link. PhishShield addresses this with a 4-tier parallel inspection pipeline:

```
+-----------------------------------------------------------------------------------+
|                            Incoming Email Ingestion                               |
|                  [Subject Line + Body Text + Sender + RFC Headers]                |
+-----------------------------------------------------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
        v                                 v                                 v
+------------------+             +------------------+             +------------------+
|   NLP & TF-IDF   |             |   Passive URL    |             |   RFC Header     |
|   ML Classifier  |             |  Security Engine |             |  Authentication  |
+------------------+             +------------------+             +------------------+
| - Text Cleaning  |             | - Regex Extractor|             | - Reply-To Match |
| - HTML Stripping |             | - IP Host Check  |             | - SPF Check      |
| - Sublinear TF   |             | - Brand Typosquat|             | - DKIM Verify    |
| - Unigram/Bigram |             | - High-Abuse TLDs|             | - DMARC Policy   |
| - Logistic Reg   |             | - Safe Handling  |             | - Display Name   |
|   Probability    |             |   (Zero Fetches) |             |   Spoofing Alert |
+------------------+             +------------------+             +------------------+
        |                                 |                                 |
        +---------------------------------+---------------------------------+
                                          |
                                          v
                    +------------------------------------------+
                    | Composite Threat Scoring Engine (0 - 100)|
                    |   Score = (ML * 0.50) + (URL * 0.30)     |
                    |         + (Header * 0.15) + (Ling * 0.05)|
                    +------------------------------------------+
                                          |
              +---------------------------+---------------------------+
              |                                                       |
              v                                                       v
+-------------------------------+                       +-------------------------------+
|     Classification Verdict    |                       |      Audit Trail Logging      |
|                               |                       |                               |
|  🔴 Phishing    (Score >= 65) |                       |  Persistent SQLite Database   |
|  🟡 Suspicious  (Score >= 35) |                       |  Captures timestamps, scores, |
|  🟢 Legitimate  (Score <  35) |                       |  URL tallies & forensic logs  |
+-------------------------------+                       +-------------------------------+
```

---

## 🔍 Multi-Tier Detection Mechanics

### Tier 1: Text NLP & TF-IDF Classifier ($50\%$ Weight)
- Decodes obfuscated HTML entities (`&amp;`, `&lt;`, `&#x20;`) and strips rendering tags.
- Replaces raw hyperlinks with a standardized `__url_token__` and money sums with `__currency_token__` to prevent overfitting.
- Computes **Sublinear TF-IDF** with unigram and bigram extraction across a $3,500$-feature vocabulary space.
- Outputs a calibrated class probability ($0.00$ to $1.00$).

### Tier 2: Passive URL Threat Inspection ($30\%$ Weight)
- **Zero-Nav Safe Handling**: Never opens, visits, or follows extracted URLs, preventing drive-by malware execution or canary token triggers.
- **Direct IP Address Detection**: Detects links hosting on raw IPv4/IPv6 addresses (e.g., `http://192.168.1.105/login`).
- **Brand Impersonation & Typosquatting**: Identifies targeted brand keywords (`paypal`, `microsoft`, `chase`, `google`, `apple`) residing outside their official domains (e.g., `paypal.account-verify.xyz`).
- **Abuse TLD Heuristics**: Detects suspicious Top-Level Domains (`.xyz`, `.top`, `.club`, `.work`, `.click`, `.buzz`, `.cam`).
- **Credential Obfuscation**: Flags presence of the `@` symbol in URLs used to disguise true hostnames.

### Tier 3: Email Header Authenticity ($15\%$ Weight)
- **Reply-To Mismatch Detection**: Alerts when the `Reply-To` domain differs from the `From` domain—a hallmark of spear-phishing and wire-fraud schemes.
- **Display Name Deception**: Catches attackers setting display names to trusted entities while using free webmail sending addresses (e.g., `PayPal Support <hacker82@gmail.com>`).
- **SPF, DKIM, and DMARC Verification**: Extracts status outcomes from `Authentication-Results` and `Received-SPF`.
- **Honest Telemetry**: Missing headers are explicitly marked as **`Unknown`** instead of fabricating false negative assurances.

### Tier 4: Linguistic Urgency Triggers ($5\%$ Weight)
- Isolates high-pressure panic keywords (`urgent`, `account suspended`, `verify immediately`, `final notice`, `wire transfer`).
- Computes uppercase character ratio (shouting) and exclamation point frequency.

---

## 📊 Machine Learning Benchmark & Results

The classifier was evaluated on a curated, balanced dataset (`dataset/emails.csv`) using a **stratified 80% train / 20% test split** with **strict deduplication** to eliminate train-test leakage.

### Benchmark Comparison

| Model | Accuracy | Precision (Phishing) | Recall (Phishing) | F1-Score | ROC-AUC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | **94.44%** | **100.00%** | **88.89%** | **0.9412** | **1.0000** | **🏆 Selected** |
| Random Forest Classifier | 88.89% | 100.00% | 77.78% | 0.8750 | 0.9877 | Candidate |

### Confusion Matrix (Test Set)
```
                  Predicted Legitimate    Predicted Phishing
Actual Legitimate          9                      0        <-- 0% False Positive Rate
Actual Phishing            1                      8        <-- High Threat Recall
```
*Artifacts saved at `models/phishing_model.joblib`, `models/tfidf_vectorizer.joblib`, and `models/metrics.json`.*

---

## 🖥️ Dashboard Walkthrough

The web dashboard is styled with a **modern dark-navy cybersecurity operations center (SOC)** theme:

1. **Email Ingestion Panel**:
   - Accepts Sender, Reply-To, Subject, Email Body, and optional raw RFC email headers.
   - **Preset Sample Dropdown**: One-click ingestion of Credential Phishing, Spear-Phishing Wire Fraud, and Legitimate Meeting invites.
2. **Threat Verdict Card**:
   - Dynamic verdict badges: `🔴 Phishing`, `🟡 Suspicious`, or `🟢 Likely Legitimate`.
   - **Animated Risk Meter**: Color-coded progress bar ($0 - 100$) showing the calibrated composite threat score.
3. **Forensic Breakdown Sections**:
   - **ML Probability Card**: Displays the underlying classifier confidence.
   - **URL Security Table**: Lists all extracted hyperlinks with individual risk flags and target hosts.
   - **Header Authentication Badges**: Shows status pills for `SPF`, `DKIM`, and `DMARC`.
   - **Linguistic Trigger Cloud**: Visualizes detected panic phrases and uppercase shout ratios.
   - **Actionable Recommendations**: Clear, contextual guidance for incident response.
4. **Persistent Audit Trail**:
   - Displays past scans recorded in SQLite with timestamps, verdicts, and risk scores.
   - Features a one-click audit clear button.
5. **Interactive ML Benchmark Modal**:
   - Accessible via the top navbar button to review algorithm metrics and confusion matrices during project defense.

---

## 📁 Project Directory Structure

```
phishing-email-detector/
├── app.py                      # Flask web server, REST endpoints, and score synthesis
├── train_model.py              # ML training, TF-IDF vectorization, and benchmark pipeline
├── email_preprocessor.py       # HTML stripper, text normalizer, and urgency extractor
├── url_analyzer.py             # Passive URL heuristic and threat analysis engine
├── header_analyzer.py          # RFC email header spoofing and SPF/DKIM/DMARC verifier
├── database.py                 # SQLite database integration for scan history
├── requirements.txt            # Python production dependencies
├── .env.example                # Template for environment configuration
├── .env                        # Local development environment configuration
├── .gitignore                  # Git ignore rules for caches, DBs, and credentials
├── README.md                   # Comprehensive technical documentation
├── dataset/
│   ├── emails.csv              # Balanced training corpus (Phishing vs Legitimate)
│   └── download_datasets.py    # Helper script to download public benchmark archives
├── models/
│   ├── phishing_model.joblib   # Saved best-performing classifier
│   ├── tfidf_vectorizer.joblib # Fitted TF-IDF vocabulary vectorizer
│   └── metrics.json            # Benchmark metrics, confusion matrix, and notes
├── templates/
│   └── index.html              # Cyber-themed Bootstrap 5 dashboard interface
├── static/
│   ├── css/style.css           # Dark navy cybersecurity theme styling
│   └── js/main.js              # Asynchronous scanning, DOM updates, and risk meter
└── tests/
    ├── __init__.py             # Test package initialization
    ├── test_analyzer.py        # Unit tests for preprocessor, URL, and header engines
    └── test_app.py             # Integration tests for Flask endpoints and DB
```

---

## 🚀 Quick Start Guide

### Windows (PowerShell)

```powershell
# 1. Navigate to the project root
cd "C:\Users\D E LL\Desktop\phishing-email-detector"

# 2. Run automated verification tests
python -m pytest tests -v

# 3. Retrain the machine learning model (Optional)
python train_model.py

# 4. Start the application
python app.py
```
> Open your browser at: **`http://127.0.0.1:5000`**

---

### Kali Linux / Ubuntu

```bash
# 1. Navigate to the project root
cd ~/Desktop/phishing-email-detector

# 2. Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install required packages
pip install --upgrade pip
pip install -r requirements.txt

# 4. Run automated tests
python3 -m pytest tests -v

# 5. Launch the application
python3 app.py
```
> Open your browser at: **`http://127.0.0.1:5000`**

---

### ☁️ Vercel Deployment & Serverless Database (Neon / Supabase)

Because Vercel executes inside serverless Lambda containers with a **read-only filesystem**, local SQLite disk writes fail with `attempt to write a readonly database`. **PhishShield** solves this with a **dual-engine architecture**:

1. **PostgreSQL Mode (Production / Vercel)**: Automatically engages when `DATABASE_URL` is set in your Vercel Environment Variables.
2. **Resilient Fallback Mode**: If PostgreSQL is not yet configured, the email scanner still performs complete ML, URL, and Header threat analysis without throwing HTTP 500 errors.

#### Step 1: Create a Free PostgreSQL Database (Neon or Supabase)
- **Option A (Neon - Recommended)**: Sign up at [neon.tech](https://neon.tech), create a free database, and copy the connection string:
  ```text
  postgresql://[user]:[password]@[endpoint].neon.tech/neondb?sslmode=require
  ```
- **Option B (Supabase)**: Sign up at [supabase.com](https://supabase.com), create a project, open **Settings > Database**, and copy the Connection String (URI).

#### Step 2: Database Schema (Auto-Created)
The table is automatically provisioned on the first connection. If you wish to run it manually in your Neon/Supabase SQL editor:
```sql
CREATE TABLE IF NOT EXISTS scan_logs (
    id SERIAL PRIMARY KEY,
    timestamp VARCHAR(64) NOT NULL,
    sender VARCHAR(255),
    subject VARCHAR(255),
    classification VARCHAR(64) NOT NULL,
    risk_level VARCHAR(64) NOT NULL,
    overall_score DOUBLE PRECISION NOT NULL,
    ml_probability DOUBLE PRECISION NOT NULL,
    url_count INTEGER DEFAULT 0,
    suspicious_url_count INTEGER DEFAULT 0,
    header_issues_count INTEGER DEFAULT 0,
    summary TEXT
);
```

#### Step 3: Configure Vercel Project Environment Variables
1. Go to your **Vercel Dashboard** $\rightarrow$ select your project $\rightarrow$ **Settings** $\rightarrow$ **Environment Variables**.
2. Add:
   - **`DATABASE_URL`**: `postgresql://[user]:[password]@[endpoint]/[dbname]?sslmode=require`
   - **`SECRET_KEY`**: `your-random-production-secret-key`
   - **`VIRUSTOTAL_API_KEY`**: *(Optional)* Your VirusTotal API key.
3. Click **Save**.
4. Trigger a redeployment by pushing to GitHub or clicking **Deployments $\rightarrow$ Redeploy** in Vercel.

---

## 🧪 Sample Threat Vectors (For Demo)

### 🔴 Attack Vector 1: Credential Harvester (PayPal Spoof)
```text
From:       Security Operations <alert@paypal-account-lock.top>
Reply-To:   harvester@darkweb-drop.xyz
Subject:    URGENT: Your PayPal Account Has Been Suspended!
Headers:    Authentication-Results: spf=fail; dkim=fail; dmarc=fail
Body:       Dear Customer, we detected unauthorized logins from Moscow.
            Verify your credentials immediately to avoid account closure:
            http://192.168.1.105/paypal/verify_identity?redirect=login.php
```
*Expected Result: `Phishing` (Score: 90+)*

---

### 🟡 Attack Vector 2: Executive Wire Transfer Fraud (Spear-Phishing)
```text
From:       Arthur Pendelton <ceo-desk@company-exec-portal.sbs>
Reply-To:   arthur.private884@gmail.com
Subject:    Confidential: Emergency invoice wire transfer required
Body:       Hi, I am in an urgent board meeting and cannot take calls.
            Please execute a wire transfer of $14,500 today using our portal:
            http://executive-wire-settlement.top/invoice
```
*Expected Result: `Phishing` / `Suspicious` (Flags Reply-To mismatch & abusive TLD)*

---

### 🟢 Benign Vector 3: Legitimate Research Sync
```text
From:       Alex Mercer <alex.mercer@cyberdefense-lab.edu>
Reply-To:   alex.mercer@cyberdefense-lab.edu
Subject:    Agenda for Thursday Cyber Security Research Sync
Headers:    Authentication-Results: spf=pass; dkim=pass; dmarc=pass
Body:       Hi team, here is our agenda for Thursday at 2:00 PM.
            Review the meeting link on Google Meet:
            https://meet.google.com/abc-defg-hij
```
*Expected Result: `Likely Legitimate` (Score: < 15)*

---

## 🧪 Automated Testing

The suite in `tests/` covers **19 unit and integration tests** to ensure functional reliability:

```powershell
python -m pytest tests -v
```

```text
tests/test_analyzer.py::TestPreprocessor::test_clean_email_text_entities_and_urls PASSED [  5%]
tests/test_analyzer.py::TestPreprocessor::test_extract_linguistic_indicators PASSED      [ 10%]
tests/test_analyzer.py::TestUrlAnalyzer::test_extract_urls PASSED                        [ 15%]
tests/test_analyzer.py::TestUrlAnalyzer::test_ip_address_detection PASSED                [ 21%]
tests/test_analyzer.py::TestUrlAnalyzer::test_legitimate_url PASSED                      [ 26%]
tests/test_analyzer.py::TestUrlAnalyzer::test_suspicious_url_ip_host PASSED              [ 31%]
tests/test_analyzer.py::TestUrlAnalyzer::test_suspicious_url_typosquatting PASSED        [ 36%]
tests/test_analyzer.py::TestHeaderAnalyzer::test_display_name_spoofing PASSED            [ 42%]
tests/test_analyzer.py::TestHeaderAnalyzer::test_parse_email_address PASSED              [ 47%]
tests/test_analyzer.py::TestHeaderAnalyzer::test_reply_to_mismatch PASSED                [ 52%]
tests/test_analyzer.py::TestHeaderAnalyzer::test_spf_dkim_auth_parsing PASSED            [ 57%]
tests/test_analyzer.py::TestHeaderAnalyzer::test_unknown_auth_status_when_headers_missing PASSED [ 63%]
tests/test_app.py::TestFlaskEndpoints::test_get_metrics_route PASSED                     [ 68%]
tests/test_app.py::TestFlaskEndpoints::test_get_samples_route PASSED                     [ 73%]
tests/test_app.py::TestFlaskEndpoints::test_history_and_clear PASSED                     [ 78%]
tests/test_app.py::TestFlaskEndpoints::test_index_route PASSED                           [ 84%]
tests/test_app.py::TestFlaskEndpoints::test_scan_empty_payload_validation PASSED         [ 89%]
tests/test_app.py::TestFlaskEndpoints::test_scan_legitimate_email PASSED                 [ 94%]
tests/test_app.py::TestFlaskEndpoints::test_scan_phishing_email PASSED                   [100%]
============================= 19 passed in 3.93s ==============================
```

---

## 🎓 Viva Defense & Interview Q&A

### Q1: Why not rely solely on Machine Learning for detection?
> **Answer**: Pure NLP ML classifiers are vulnerable to **adversarial wording** and **spear-phishing**. Attackers can craft grammatically pristine, friendly text that scores as "Legitimate" while embedding an exploit link. Combining ML with deterministic URL inspection (raw IP detection, typosquatting) and RFC header authentication creates an interlocking defense that catches multi-vector evasion.

### Q2: How does the system defend against zero-day phishing links?
> **Answer**: Rather than relying exclusively on domain blacklists (which are ineffective against domains registered hours earlier), PhishShield inspects **structural indicators**: direct IP hosts, multiple subdomain layers (`login.microsoft.com.account-verify.xyz`), open-redirect query parameters, and high-abuse TLDs.

### Q3: How did you prevent data leakage during model training?
> **Answer**: 
> 1. All email texts were deduplicated prior to splitting.
> 2. An $80/20$ stratified split preserved class distributions across training and testing sets.
> 3. The `TfidfVectorizer` was fitted strictly on `X_train` (`fit_transform`) and only used to `transform` `X_test`, ensuring zero test set distribution knowledge leaked into training.

### Q4: What are the primary limitations of the architecture?
> **Answer**:
> - **Homoglyph & Punycode Attacks**: Non-Latin homoglyphs (e.g. Cyrillic `а` replacing Latin `a`) require specialized unicode normalization.
> - **Image-Only Phishing**: Phishing messages embedded entirely inside PNG/JPEG attachments require an OCR (Optical Character Recognition) pipeline.
> - **Model Drift**: Generative AI email lures evolve; models should be retrained periodically against incoming threat feeds.

---

## 🔒 Security Safeguards

- **Safe Passive URL Analysis**: The system analyzes URLs via static string parsing and regex heuristics. It **never makes HTTP GET/HEAD requests** to extracted links.
- **Request Size Limits**: Ingestion is capped at **2 MB** (`MAX_CONTENT_LENGTH`) to guard against memory exhaustion.
- **Credential Protection**: API keys and environment configurations are kept in `.env` and omitted from version control via `.gitignore`.
- **Probabilistic Disclaimer**: Clearly states that predictions are analytical aids and not an absolute security guarantee.

---

## 👤 Author & Acknowledgments

- **Developer**: B.Tech Cyber Security Student
- **Technologies Used**: Python, Flask, Scikit-Learn, Pandas, NumPy, HTML5, CSS3, JavaScript, Bootstrap 5, SQLite
- **Corpora Reference**: Incorporates design patterns from the SpamAssassin Public Corpus and Nazario Phishing Feeds.

*Designed for research, educational purposes, and cybersecurity technical portfolio defense.*
