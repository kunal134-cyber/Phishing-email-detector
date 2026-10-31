# This file ensures the models/ directory is tracked by git.
# The following files in this directory must be committed for Vercel deployment:
#   - phishing_model.joblib       (trained Logistic Regression classifier)
#   - tfidf_vectorizer.joblib     (fitted TF-IDF vocabulary vectorizer)
#   - metrics.json                (benchmark metrics and training report)
#
# To regenerate these files locally, run:
#   python train_model.py
