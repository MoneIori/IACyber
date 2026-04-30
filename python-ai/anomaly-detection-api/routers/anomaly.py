from fastapi import APIRouter
from schemas.events import BatchRequest, BatchResult, AnomalyResult, EventFeatures
from models import isolation_forest_model as model

router = APIRouter(tags=["Anomaly Detection"])


def load_model():
    model.load()


@router.post("/detect", response_model=BatchResult)
def detect_anomalies(request: BatchRequest) -> BatchResult:
    features_list = [_to_feature_dict(e) for e in request.events]
    predictions = model.predict(features_list)

    results = [
        AnomalyResult(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            is_anomaly=pred["is_anomaly"],
            anomaly_score=pred["anomaly_score"],
            confidence=pred["confidence"],
            explanation=pred["explanation"],
        )
        for event, pred in zip(request.events, predictions)
    ]

    return BatchResult(
        results=results,
        processed=len(results),
        anomalies_found=sum(1 for r in results if r.is_anomaly),
    )


def _to_feature_dict(event: EventFeatures) -> dict:
    return {
        "severity_score": event.severity_score,
        "bytes_sent": event.bytes_sent or 0,
        "bytes_received": event.bytes_received or 0,
        "duration_ms": event.duration_ms or 0,
        "failed_logins_last_hour": event.failed_logins_last_hour or 0,
        "unique_destinations_last_hour": event.unique_destinations_last_hour or 0,
        "hour_of_day": event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour,
        "day_of_week": event.day_of_week if event.day_of_week is not None else event.timestamp.weekday(),
        "source_port": event.source_port or 0,
        "destination_port": event.destination_port or 0,
    }
