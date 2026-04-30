import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# MITRE ATT&CK for Containers — 10 classes
MITRE_CLASSES = [
    {"tactic": "Initial Access",        "technique": "Exploit Public-Facing Application", "tactic_id": "TA0001", "technique_id": "T1190"},
    {"tactic": "Execution",             "technique": "Command and Scripting Interpreter",  "tactic_id": "TA0002", "technique_id": "T1059"},
    {"tactic": "Persistence",           "technique": "Scheduled Task/Job",                 "tactic_id": "TA0003", "technique_id": "T1053"},
    {"tactic": "Privilege Escalation",  "technique": "Escape to Host",                     "tactic_id": "TA0004", "technique_id": "T1611"},
    {"tactic": "Defense Evasion",       "technique": "Modify Cloud Compute Infrastructure", "tactic_id": "TA0005", "technique_id": "T1578"},
    {"tactic": "Credential Access",     "technique": "Unsecured Credentials",              "tactic_id": "TA0006", "technique_id": "T1552"},
    {"tactic": "Discovery",             "technique": "Container and Resource Discovery",   "tactic_id": "TA0007", "technique_id": "T1613"},
    {"tactic": "Lateral Movement",      "technique": "Lateral Tool Transfer",              "tactic_id": "TA0008", "technique_id": "T1570"},
    {"tactic": "Collection",            "technique": "Data from Local System",             "tactic_id": "TA0009", "technique_id": "T1005"},
    {"tactic": "Exfiltration",          "technique": "Exfiltration Over Alternative Protocol", "tactic_id": "TA0010", "technique_id": "T1048"},
]

FEATURE_COLUMNS = [
    "severity_score",
    "bytes_sent",
    "bytes_received",
    "failed_logins",
    "unique_destinations",
    "hour_of_day",
    "destination_port",
]

NUM_CLASSES = len(MITRE_CLASSES)

MODEL_PATH = Path("models/mitre_classifier.joblib")

_model: XGBClassifier | None = None


def load() -> None:
    global _model
    if MODEL_PATH.exists():
        _model = joblib.load(MODEL_PATH)
        logger.info("MITRE XGBoost classifier loaded from disk")
    else:
        logger.warning("No trained model found — training on synthetic data")
        _train_default()


def _generate_synthetic_data() -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(42)
    samples_per_class = 300
    X_parts, y_parts = [], []

    # Class 0 — Initial Access T1190: high severity, traffic on port 443/80, low failed logins
    for cls_idx in range(NUM_CLASSES):
        n = samples_per_class
        if cls_idx == 0:  # Initial Access
            X = np.column_stack([
                rng.uniform(6, 10, n),           # severity_score
                rng.integers(1000, 50000, n),    # bytes_sent
                rng.integers(5000, 100000, n),   # bytes_received
                rng.integers(0, 3, n),           # failed_logins
                rng.integers(1, 5, n),           # unique_destinations
                rng.integers(8, 18, n),          # hour_of_day
                rng.choice([80, 443, 8080], n),  # destination_port
            ])
        elif cls_idx == 1:  # Execution
            X = np.column_stack([
                rng.uniform(4, 9, n),
                rng.integers(500, 10000, n),
                rng.integers(500, 10000, n),
                rng.integers(0, 2, n),
                rng.integers(1, 3, n),
                rng.integers(0, 23, n),
                rng.choice([22, 2375, 2376, 8080], n),
            ])
        elif cls_idx == 2:  # Persistence
            X = np.column_stack([
                rng.uniform(3, 7, n),
                rng.integers(100, 5000, n),
                rng.integers(100, 5000, n),
                rng.integers(0, 1, n),
                rng.integers(1, 2, n),
                rng.integers(1, 5, n),            # odd hours
                rng.choice([22, 5432, 3306], n),
            ])
        elif cls_idx == 3:  # Privilege Escalation
            X = np.column_stack([
                rng.uniform(7, 10, n),
                rng.integers(1000, 20000, n),
                rng.integers(1000, 20000, n),
                rng.integers(0, 5, n),
                rng.integers(1, 4, n),
                rng.integers(0, 23, n),
                rng.choice([2375, 2376, 6443], n),
            ])
        elif cls_idx == 4:  # Defense Evasion
            X = np.column_stack([
                rng.uniform(4, 8, n),
                rng.integers(500, 15000, n),
                rng.integers(500, 15000, n),
                rng.integers(0, 2, n),
                rng.integers(1, 6, n),
                rng.integers(0, 23, n),
                rng.choice([443, 8443, 9090], n),
            ])
        elif cls_idx == 5:  # Credential Access
            X = np.column_stack([
                rng.uniform(5, 9, n),
                rng.integers(100, 5000, n),
                rng.integers(100, 5000, n),
                rng.integers(10, 100, n),          # many failed logins
                rng.integers(1, 3, n),
                rng.integers(0, 23, n),
                rng.choice([22, 3389, 389, 636], n),
            ])
        elif cls_idx == 6:  # Discovery
            X = np.column_stack([
                rng.uniform(2, 6, n),
                rng.integers(100, 3000, n),
                rng.integers(500, 10000, n),
                rng.integers(0, 2, n),
                rng.integers(20, 200, n),           # many unique destinations (scanning)
                rng.integers(8, 20, n),
                rng.choice([22, 80, 443, 8080, 9090, 2375], n),
            ])
        elif cls_idx == 7:  # Lateral Movement
            X = np.column_stack([
                rng.uniform(5, 9, n),
                rng.integers(5000, 50000, n),
                rng.integers(5000, 50000, n),
                rng.integers(0, 5, n),
                rng.integers(5, 30, n),
                rng.integers(0, 23, n),
                rng.choice([22, 445, 5985, 5986], n),
            ])
        elif cls_idx == 8:  # Collection
            X = np.column_stack([
                rng.uniform(3, 7, n),
                rng.integers(100, 5000, n),
                rng.integers(50000, 500000, n),    # large bytes_received (reading data)
                rng.integers(0, 2, n),
                rng.integers(1, 4, n),
                rng.integers(1, 6, n),              # night hours
                rng.choice([5432, 3306, 27017, 6379], n),
            ])
        else:  # Exfiltration
            X = np.column_stack([
                rng.uniform(6, 10, n),
                rng.integers(100000, 1000000, n),  # large bytes_sent (exfiltrating)
                rng.integers(100, 5000, n),
                rng.integers(0, 3, n),
                rng.integers(1, 5, n),
                rng.choice([1, 2, 3, 4, 23], n),   # deep night
                rng.choice([53, 443, 4444, 8443], n),
            ])

        X_parts.append(X.astype(np.float32))
        y_parts.append(np.full(n, cls_idx, dtype=np.int32))

    return np.vstack(X_parts), np.concatenate(y_parts)


def _train_default() -> None:
    global _model
    X, y = _generate_synthetic_data()

    _model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=NUM_CLASSES,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )
    _model.fit(X, y)

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(_model, MODEL_PATH)
    logger.info("MITRE XGBoost classifier trained and saved to %s", MODEL_PATH)


def predict(features_list: list[dict]) -> list[dict]:
    if _model is None:
        raise RuntimeError("Model not loaded — call load() first")

    df = pd.DataFrame(features_list)[FEATURE_COLUMNS].fillna(0).astype(np.float32)
    proba = _model.predict_proba(df)

    results = []
    for row_proba in proba:
        cls_idx = int(np.argmax(row_proba))
        confidence = float(row_proba[cls_idx])
        mitre = MITRE_CLASSES[cls_idx]
        results.append({
            "tactic": mitre["tactic"],
            "technique": mitre["technique"],
            "tactic_id": mitre["tactic_id"],
            "technique_id": mitre["technique_id"],
            "confidence": confidence,
            "mitre_url": f"https://attack.mitre.org/techniques/{mitre['technique_id']}/",
        })

    return results
