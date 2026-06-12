import os
import random
import math
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

FEATURE_COLUMNS = [
    "url_length", "num_dots", "num_hyphen", "contains_ip",
    "has_https", "domain_age", "suspicious_words", "redirect_count", "entropy_score",
]

SUSPICIOUS_WORDS = ["login", "verify", "bank", "paypal", "wallet", "free", "gift", "crypto"]


def _entropy(s):
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def generate_sample(label):
    if label == 1:
        words = random.sample(SUSPICIOUS_WORDS, k=random.randint(2, 4))
        domain = f"{random.choice(words)}-{random.randint(100,9999)}.{random.choice(['xyz','tk','ru','click','info'])}"
        path = "/" + "-".join(words[:2])
        url = f"http://{domain}{path}"
        return {
            "url_length": len(url),
            "num_dots": url.count("."),
            "num_hyphen": url.count("-"),
            "contains_ip": random.choice([0, 0, 0, 1]),
            "has_https": random.choice([0, 0, 1]),
            "domain_age": random.randint(1, 45),
            "suspicious_words": random.randint(2, 5),
            "redirect_count": random.randint(1, 5),
            "entropy_score": round(_entropy(url), 4),
            "label": 1,
        }
    else:
        brands = ["google", "github", "microsoft", "amazon", "stripe", "cloudflare", "linkedin"]
        brand = random.choice(brands)
        url = f"https://{brand}.com/{random.choice(['docs','about','login','products'])}"
        return {
            "url_length": len(url),
            "num_dots": url.count("."),
            "num_hyphen": url.count("-"),
            "contains_ip": 0,
            "has_https": 1,
            "domain_age": random.randint(500, 8000),
            "suspicious_words": random.randint(0, 1),
            "redirect_count": random.randint(0, 1),
            "entropy_score": round(_entropy(url), 4),
            "label": 0,
        }


def generate_dataset(n_samples=3000):
    rows = []
    for _ in range(n_samples // 2):
        rows.append(generate_sample(0))
        rows.append(generate_sample(1))
    df = pd.DataFrame(rows)
    df.to_csv(DATASET_PATH, index=False)
    return df


def train():
    if os.path.exists(DATASET_PATH):
        df = pd.read_csv(DATASET_PATH)
    else:
        df = generate_dataset()

    X = df[FEATURE_COLUMNS]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
