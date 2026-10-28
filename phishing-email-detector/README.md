# PhishShield | AI-Powered Phishing Email Detector

A production-grade, multi-layered **Phishing and Spear-Phishing Detection System** developed for a **B.Tech Cyber Security** capstone portfolio. The system combines Natural Language Processing (TF-IDF), supervised Machine Learning (Logistic Regression vs. Random Forest), passive URL threat heuristics, and RFC 822/5322 email header authenticity verification (SPF, DKIM, DMARC).

---

## Table of Contents
1. [Project Overview & Cyber Defense Objectives](#project-overview--cyber-defense-objectives)
2. [Architecture & Detection Pipeline](#architecture--detection-pipeline)
3. [Core Security Features](#core-security-features)
4. [Machine Learning Benchmark & Evaluation](#machine-learning-benchmark--evaluation)
5. [Project Structure](#project-structure)
6. [Installation & Execution Guide](#installation--execution-guide)
   - [Windows (PowerShell)](#windows-powershell-setup)
   - [Kali Linux / Ubuntu](#kali-linux--ubuntu-setup)
7. [Dataset Acquisition & Leakage Prevention](#dataset-acquisition--leakage-prevention)
8. [Automated Testing](#automated-testing)
9. [Limitations & Viva Defense Q&A](#limitations--viva-defense-qa)
10. [Responsible Disclosure & Disclaimer](#responsible-disclosure--disclaimer)

---

## Project Overview & Cyber Defense Objectives

Traditional spam filters often miss targeted spear-phishing campaigns that mimic corporate communications or use newly registered malicious domains. **PhishShield** addresses this challenge with a **defense-in-depth analytical engine**:

1. **Linguistic & Semantic NLP Analysis**: Tokenizes email content, normalizes obfuscated text, strips raw HTML entities, and isolates emotional coercion/urgency patterns.
2. **Supervised Machine Learning**: Evaluates email text against a high-dimensional TF-IDF feature space using trained and calibrated classifiers.
3. **Passive URL Threat Inspection**: Inspects extracted hyperlinks for direct IP addresses, typosquatting/brand impersonation, excessive subdomain depth, and high-abuse TLDs without ever following or opening dangerous links.
4. **Header Integrity & Spoofing Audit**: Parses raw RFC email headers to detect Reply-To mismatching, display name deception, and cryptographic authentication records (SPF, DKIM, and DMARC).
5. **Auditable SQLite Logging**: Records scan telemetry and risk scores for retrospective security incident analysis.

---

## Architecture & Detection Pipeline

```
+-----------------------------------------------------------------------------------+
|                                Raw Email Ingestion                                |
|                  (Subject + Body + Sender + Optional RFC Headers)                 |
+-----------------------------------------------------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
        v                                 v                                 v
+------------------+             +------------------+             +------------------+
|  NLP & TF-IDF    |             |  Passive URL     |             |  Email Header    |
|  Classification  |             |  Security Engine |             |  Authentication  |
+------------------+             +------------------+             +------------------+
| - Text Cleaning  |             | - Regex Extract  |             | - Reply-To Match |
| - HTML Stripping |             | - IP Host Check  |             | - SPF / DKIM     |
| - TF-IDF Vectors |             | - Brand Typosquat|             | - DMARC Policy   |
| - Logistic Reg / |             | - Abuse TLDs     |             | - Display Name   |
|   Random Forest  |             | - Safe Handling  |             |   Spoofing       |
+------------------+             +------------------+             +------------------+
        |                                 |                                 |
        +---------------------------------+---------------------------------+
                                          |
                                          v
                     +-----------------------------------------+
                     | Composite Risk Score & Calibrated Gauge |
                     |      (0 - 100 Calibrated Threat Index)  |
                     +-----------------------------------------+
                                          |
              +---------------------------+---------------------------+
              |                                                       |
              v                                                       v
+-------------------------------+                       +-------------------------------+
|     Classification Verdict    |                       |      Audit Trail Logging      |
| [Phishing | Suspicious | Legit]|                       |   (SQLite Local Database)     |
+-------------------------------+                       +-------------------------------+
```

---

## Core Security Features

- **Safe Static URL Inspection**: Extracted hyperlinks are analyzed strictly through passive string and host heuristics. The system **never opens, navigates to, or fetches remote content**, preventing drive-by downloads and token leakage.
- **Header Authentication Parser**: Parses `Authentication-Results` and `Received-SPF`. Crucially, when headers are absent, the system labels results as **Unknown** rather than fabricating false-positive assurances.
- **Calibrated Scoring Engine**: Combines the probabilistic ML score ($50\%$), URL heuristics ($30\%$), header integrity ($15\%$), and linguistic urgency indicators ($5\%$). High-confidence indicators (such as raw IP hosts or SPF failures) immediately elevate the threat level.
- **DoS & Payload Guards**: Flask application config enforces strict request size limits ($2\text{ MB}$) to prevent memory exhaustion attacks.
- **Threat Intelligence Extensibility**: Supports integration with VirusTotal v3 via `VIRUSTOTAL_API_KEY` in `.env`, while maintaining full offline detection capability if no API key is provided.

---

## Machine Learning Benchmark & Evaluation

The machine learning pipeline evaluates both **Logistic Regression** and **Random Forest** on an $80/20$ stratified split with strict duplicate deduplication to prevent data leakage.

### Benchmark Results (Evaluated Test Set)

| Classifier Algorithm | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression (Selected)** | **94.44%** | **100.00%** | **88.89%** | **0.9412** | **1.0000** |
| Random Forest Classifier | 88.89% | 100.00% | 77.78% | 0.8750 | 0.9877 |

### Confusion Matrix (Logistic Regression)
- **True Negatives (Legitimate classified as Legitimate)**: 9
- **False Positives (Legitimate misclassified as Phishing)**: 0 ($0\%$ False Alarm Rate)
- **False Negatives (Phishing misclassified as Legitimate)**: 1
- **True Positives (Phishing correctly identified)**: 8

*Metrics and hyperparameters are automatically recorded in `models/metrics.json` upon every training run.*

---

## Project Structure

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

## Installation & Execution Guide

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- `pip` package manager

---

### Windows (PowerShell) Setup

1. **Clone or navigate to the project directory**:
   ```powershell
   cd "C:\Users\D E LL\Desktop\phishing-email-detector"
   ```

2. **Create and activate a virtual environment (Recommended)**:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

4. **Train the Machine Learning Model**:
   ```powershell
   python train_model.py
   ```
   *(This trains Logistic Regression & Random Forest, compares metrics, and exports artifacts to `models/`)*

5. **Run the Automated Test Suite**:
   ```powershell
   python -m pytest tests -v
   ```

6. **Launch the Web Application**:
   ```powershell
   python app.py
   ```
   Open your web browser and navigate to: **`http://127.0.0.1:5000`**

---

### Kali Linux / Ubuntu Setup

1. **Open terminal and navigate to the project**:
   ```bash
   cd ~/Desktop/phishing-email-detector
   ```

2. **Create and activate virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install required packages**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Train the ML model**:
   ```bash
   python3 train_model.py
   ```

5. **Execute tests**:
   ```bash
   python3 -m pytest tests -v
   ```

6. **Start Flask server**:
   ```bash
   python3 app.py
   ```
   Open browser at **`http://127.0.0.1:5000`**

---

## Dataset Acquisition & Leakage Prevention

### Included Balanced Corpus
The project includes a curated dataset (`dataset/emails.csv`) containing realistic phishing variants (credential harvesters, BEC wire fraud, tax refund scams, shipping alerts) and legitimate corporate communications (meeting agendas, GitHub notifications, invoices, travel receipts).

### Data Leakage Safeguards
1. **Deduplication**: Exact text duplicates are removed before splitting to ensure no overlap between training and testing folds.
2. **Stratification**: `train_test_split(..., stratify=y)` ensures identical class balance across training ($80\%$) and testing ($20\%$) sets.
3. **TF-IDF Isolation**: The vectorizer is fitted **strictly on the training set** (`fit_transform`) and subsequently transforms test inputs (`transform`) without learning test distributions.

### Scaling to Enterprise Corpora
To scale training with tens of thousands of real-world emails from public archives (such as SpamAssassin or Nazario Phishing Corpora), execute:
```bash
python dataset/download_datasets.py
```
Then train on the expanded corpus:
```bash
python train_model.py --dataset dataset/expanded_emails.csv
```

---

## Automated Testing

The automated test suite (`tests/`) validates end-to-end reliability across 19 unit and integration test cases:
- Preprocessing and HTML entity unescaping
- Urgency keyword identification and exclamation counting
- Extraction of IPv4 and IPv6 URLs
- Detection of brand typosquatting (e.g. `paypal-security.xyz`)
- Email header parsing: Reply-To mismatches and display name spoofing
- RFC authentication status extraction (Pass, Fail, SoftFail, Unknown)
- REST API validation (`/api/scan`, `/api/metrics`, `/api/samples`, `/api/history`, `/api/clear-history`)

Run tests with verbose reporting:
```bash
python -m pytest tests -v
```

---

## Limitations & Viva Defense Q&A

### 1. Why combine Machine Learning with Heuristics rather than using ML alone?
> **Answer**: Pure NLP models can be bypassed by attackers who write polite, neutral text while embedding a malicious link (spear-phishing). By combining ML text classification with deterministic URL inspection (checking for raw IP addresses, typosquatting, high-abuse TLDs) and header verification, the system detects multi-vector attacks that evade single-layer filters.

### 2. How does the system handle zero-day phishing links?
> **Answer**: Even if a domain is newly registered and unknown to threat-intelligence databases, the system's URL heuristics inspect structural indicators such as direct IP address usage, excessive subdomain levels (e.g., `login.microsoft.com.attacker.xyz`), and suspicious TLDs.

### 3. What are the key limitations of the model?
> - **Homoglyph & Internationalized Domain Name (IDN) Attacks**: Advanced attackers using Cyrillic homoglyphs (e.g., `pаypal.com` with Cyrillic 'а') require dedicated punycode decoders.
> - **Image-Only Phishing**: Attackers who send emails containing text rendered inside an image require Optical Character Recognition (OCR) integration.
> - **Zero-Day Retraining**: The ML model requires periodic fine-tuning with fresh threat feeds to counter evolving generative AI phishing lures.

---

## Responsible Disclosure & Disclaimer

**Notice**: This application is built as an analytical defense tool for academic and educational purposes. The composite score and classifications are probabilistic risk assessments and do not constitute an infallible security guarantee. Never disclose confidential credentials or private company emails to unauthorized third-party platforms.
