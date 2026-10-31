"""
Model Training & Machine Learning Pipeline for Phishing Email Detection.
Compares Logistic Regression vs. Random Forest, evaluates metrics,
and saves the trained vectorizer and best-performing model artifacts.
"""

import os
import json
import argparse
from datetime import datetime
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from email_preprocessor import clean_email_text

BASE_DIR = os.path.dirname(__file__)
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "emails.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")


def train_and_evaluate(dataset_csv: str = DATASET_PATH):
    """
    Executes full ML training pipeline:
    1. Loads and deduplicates dataset
    2. Cleans text using NLP preprocessor
    3. Performs stratified 80/20 train/test split
    4. Computes TF-IDF vectorization (unigrams + bigrams)
    5. Trains Logistic Regression & Random Forest
    6. Calculates precision, recall, F1, ROC-AUC, confusion matrix
    7. Saves winning model and evaluation metrics to disk
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    print("=" * 65)
    print("  PHISHING EMAIL DETECTOR - MACHINE LEARNING TRAINING PIPELINE")
    print("=" * 65)
    print(f"[*] Loading dataset from: {dataset_csv}")

    if not os.path.exists(dataset_csv):
        raise FileNotFoundError(f"Dataset file not found at: {dataset_csv}")

    df = pd.read_csv(dataset_csv)
    print(f"[+] Raw samples loaded: {len(df)}")

    # Basic schema validation
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain 'text' and 'label' columns.")

    # Drop missing values
    df = df.dropna(subset=["text", "label"])

    # Preprocess text
    print("[*] Preprocessing email text and normalizing tokens...")
    df["clean_text"] = df["text"].apply(clean_email_text)

    # Filter out empty texts after cleaning
    df = df[df["clean_text"].str.strip() != ""]

    # Prevent data leakage: drop exact duplicates
    initial_len = len(df)
    df = df.drop_duplicates(subset=["clean_text"])
    dedup_len = len(df)
    print(f"[+] Deduplication complete: {dedup_len} unique emails retained ({initial_len - dedup_len} duplicates removed)")

    # Class distribution check
    phishing_count = int(df["label"].sum())
    legit_count = int(len(df) - phishing_count)
    print(f"[+] Class Balance -> Phishing (1): {phishing_count} | Legitimate (0): {legit_count}")

    if phishing_count < 5 or legit_count < 5:
        raise ValueError("Dataset must contain at least 5 samples of each class.")

    # Stratified Train-Test Split (80% Train, 20% Test)
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df["clean_text"],
        df["label"],
        test_size=0.20,
        random_state=42,
        stratify=df["label"]
    )
    print(f"[+] Dataset Split -> Training: {len(X_train_raw)} | Testing: {len(X_test_raw)}")

    # Feature Extraction: TF-IDF Vectorizer
    print("[*] Vectorizing with TF-IDF (Unigram + Bigram, Sublinear TF)...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=3500,
        sublinear_tf=True,
        min_df=1
    )
    X_train_vec = vectorizer.fit_transform(X_train_raw)
    X_test_vec = vectorizer.transform(X_test_raw)
    print(f"[+] TF-IDF Feature Space Dimensions: {X_train_vec.shape[1]} vocabulary features")

    # Define candidate classifiers
    candidates = {
        "Logistic Regression": LogisticRegression(
            C=1.5,
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=120,
            max_depth=20,
            class_weight="balanced",
            random_state=42
        )
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_model_obj = None

    print("\n" + "-" * 65)
    print("  MODEL EVALUATION & BENCHMARK")
    print("-" * 65)

    for name, clf in candidates.items():
        print(f"\n[*] Training {name}...")
        clf.fit(X_train_vec, y_train)

        # Predictions
        y_pred = clf.predict(X_test_vec)
        y_prob = clf.predict_proba(X_test_vec)[:, 1] if hasattr(clf, "predict_proba") else y_pred

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        try:
            auc = float(roc_auc_score(y_test, y_prob))
        except ValueError:
            auc = 0.5

        cm = confusion_matrix(y_test, y_pred).tolist()

        print(f"    - Accuracy:        {acc * 100:.2f}%")
        print(f"    - Precision:       {prec * 100:.2f}%")
        print(f"    - Recall:          {rec * 100:.2f}%")
        print(f"    - F1-Score:        {f1:.4f}")
        print(f"    - ROC-AUC:         {auc:.4f}")
        print(f"    - Confusion Matrix (TN, FP, FN, TP): {cm}")

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "confusion_matrix": {
                "true_negative": cm[0][0] if len(cm) > 0 and len(cm[0]) > 0 else 0,
                "false_positive": cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0,
                "false_negative": cm[1][0] if len(cm) > 1 and len(cm[1]) > 0 else 0,
                "true_positive": cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0
            }
        }

        # Model selection: prefer higher F1-score with tie-break on precision
        if f1 > best_f1 or (f1 == best_f1 and prec > results.get(best_model_name, {}).get("precision", 0)):
            best_f1 = f1
            best_model_name = name
            best_model_obj = clf

    print("\n" + "=" * 65)
    print(f"[+] SELECTED BEST CLASSIFIER: {best_model_name} (F1: {best_f1:.4f})")
    print("=" * 65)

    # Save artifacts
    model_save_path = os.path.join(MODELS_DIR, "phishing_model.joblib")
    vectorizer_save_path = os.path.join(MODELS_DIR, "tfidf_vectorizer.joblib")
    metrics_save_path = os.path.join(MODELS_DIR, "metrics.json")

    joblib.dump(best_model_obj, model_save_path)
    joblib.dump(vectorizer, vectorizer_save_path)
    print(f"[+] Saved model to: {model_save_path}")
    print(f"[+] Saved vectorizer to: {vectorizer_save_path}")

    metrics_payload = {
        "timestamp": datetime.now().isoformat(),
        "selected_model": best_model_name,
        "dataset_stats": {
            "total_samples": len(df),
            "phishing_samples": phishing_count,
            "legitimate_samples": legit_count,
            "train_samples": len(X_train_raw),
            "test_samples": len(X_test_raw),
            "vocabulary_size": X_train_vec.shape[1]
        },
        "models_evaluated": results,
        "limitations": [
            "Model is trained on representative synthetic and curated samples; zero-day phishing lures may require periodic model retraining.",
            "Text TF-IDF features alone do not capture obfuscated redirect chains; the system supplements ML predictions with deterministic URL and header heuristics.",
            "Email bodies with non-Latin scripts or extreme homoglyph attacks should be inspected with additional visual similarity tooling."
        ]
    }

    with open(metrics_save_path, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"[+] Saved evaluation metrics to: {metrics_save_path}")
    return metrics_payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Phishing Email Classifier")
    parser.add_argument("--dataset", type=str, default=DATASET_PATH, help="Path to custom CSV dataset")
    args = parser.parse_args()
    train_and_evaluate(args.dataset)
