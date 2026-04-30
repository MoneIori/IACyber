import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

FEATURE_COLUMNS = [
    "severity_score",
    "bytes_sent",
    "bytes_received",
    "duration_ms",
    "failed_logins_last_hour",
    "unique_destinations_last_hour",
    "hour_of_day",
    "day_of_week",
    "source_port",
    "destination_port",
]

MODEL_PATH = Path("models/isolation_forest.joblib")
SCALER_PATH = Path("models/scaler.joblib")

_model: IsolationForest | None = None
_scaler: StandardScaler | None = None


def load() -> None:
    global _model, _scaler
    if MODEL_PATH.exists() and SCALER_PATH.exists():
        _model = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)
        logger.info("Isolation Forest model loaded from disk")
    else:
        logger.warning("No trained model found — fitting default model on synthetic data")
        _train_default()


def _train_default() -> None:
    global _model, _scaler
    rng = np.random.default_rng(42)
    X = rng.normal(loc=0, scale=1, size=(1000, len(FEATURE_COLUMNS)))

    _scaler = StandardScaler()
    X_scaled = _scaler.fit_transform(X)

    _model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    _model.fit(X_scaled)

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(_model, MODEL_PATH)
    joblib.dump(_scaler, SCALER_PATH)
    logger.info("Default Isolation Forest trained and saved")


def predict(features_list: list[dict]) -> list[dict]:
    if _model is None or _scaler is None:
        raise RuntimeError("Model not loaded — call load() first")

    df = pd.DataFrame(features_list)[FEATURE_COLUMNS].fillna(0)
    X_scaled = _scaler.transform(df)

    # IsolationForest: -1 = anomaly, 1 = normal
    predictions = _model.predict(X_scaled)
    scores = _model.score_samples(X_scaled)

    # Normalize scores to [0, 1] where 1 = most anomalous
    normalized = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)

    results = []
    for i, (pred, score, norm_score) in enumerate(zip(predictions, scores, normalized)):
        is_anomaly = pred == -1
        results.append({
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": float(norm_score),
            "confidence": float(min(abs(score) / 0.5, 1.0)),
            "explanation": _explain(df.iloc[i], is_anomaly),
        })

    return results


def _explain(row: pd.Series, is_anomaly: bool) -> list[str]:
    explanations = []
    if not is_anomaly:
        return explanations
    if row.get("failed_logins_last_hour", 0) > 10:
        explanations.append("High number of failed logins in the last hour")
    if row.get("unique_destinations_last_hour", 0) > 50:
        explanations.append("Unusual number of unique destination IPs (possible C2 beacon)")
    if row.get("bytes_sent", 0) > 100_000_000:
        explanations.append("Large data exfiltration volume detected")
    if row.get("hour_of_day", 12) in (1, 2, 3, 4):
        explanations.append("Activity at unusual hour (1-4 AM)")
    if not explanations:
        explanations.append("Statistical anomaly — deviates significantly from baseline")
    return explanations
