"""
Dataset Helper Script for Large-Scale Phishing & Legitimate Corpora.
Provides utility functions and guidelines to download, parse, and merge
real-world public corpora such as SpamAssassin and Nazario Phishing feeds.
"""

import os
import urllib.request
import tarfile
import pandas as pd
from email import policy
from email.parser import BytesParser

DATASET_DIR = os.path.dirname(__file__)
RAW_CACHE_DIR = os.path.join(DATASET_DIR, "raw_corpora")

PUBLIC_SOURCES = {
    "spamassassin_easy_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "spamassassin_spam": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2"
}


def download_and_extract_source(name: str, url: str) -> str:
    """Download tarball from official archive and extract it safely."""
    os.makedirs(RAW_CACHE_DIR, exist_ok=True)
    archive_path = os.path.join(RAW_CACHE_DIR, f"{name}.tar.bz2")
    extract_target = os.path.join(RAW_CACHE_DIR, name)

    if not os.path.exists(archive_path):
        print(f"[*] Downloading {name} from {url}...")
        urllib.request.urlretrieve(url, archive_path)
        print(f"[+] Download complete: {archive_path}")

    if not os.path.exists(extract_target):
        print(f"[*] Extracting {archive_path}...")
        with tarfile.open(archive_path, "r:bz2") as tar:
            tar.extractall(extract_target)
        print(f"[+] Extracted to: {extract_target}")

    return extract_target


def parse_email_directory(folder_path: str, label: int) -> list[dict]:
    """Parse raw RFC-822 email files into text and label dictionaries."""
    records = []
    parser = BytesParser(policy=policy.default)

    for root, _, files in os.walk(folder_path):
        for f in files:
            file_path = os.path.join(root, f)
            try:
                with open(file_path, "rb") as fp:
                    msg = parser.parse(fp)
                    subject = str(msg.get("Subject", ""))
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body += part.get_payload(decode=True).decode(errors="ignore") + "\n"
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body = payload.decode(errors="ignore")

                    combined_text = f"{subject}\n{body}".strip()
                    if combined_text:
                        records.append({
                            "text": combined_text[:3000],  # Reasonable length cap
                            "label": label
                        })
            except Exception:
                continue
    return records


def build_benchmark_dataset(output_filename: str = "expanded_emails.csv"):
    """
    Downloads and parses public benchmark archives to create an expanded dataset.
    Requires internet connectivity and bypasses sandbox.
    """
    print("[*] Initiating benchmark dataset builder...")
    all_rows = []

    for name, url in PUBLIC_SOURCES.items():
        is_spam = 1 if "spam" in name else 0
        try:
            target_folder = download_and_extract_source(name, url)
            rows = parse_email_directory(target_folder, is_spam)
            print(f"[+] Parsed {len(rows)} emails from {name}")
            all_rows.extend(rows)
        except Exception as e:
            print(f"[-] Could not process {name}: {e}")

    if all_rows:
        df = pd.DataFrame(all_rows).drop_duplicates(subset=["text"])
        out_path = os.path.join(DATASET_DIR, output_filename)
        df.to_csv(out_path, index=False)
        print(f"[+] Successfully saved {len(df)} samples to {out_path}")


if __name__ == "__main__":
    print("=" * 60)
    print("Email Dataset Utility for Cybersecurity Researchers")
    print("=" * 60)
    print("Standard sample dataset already exists at: dataset/emails.csv")
    print("To download the large multi-thousand SpamAssassin benchmark, run this script.")
