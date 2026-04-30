from fastapi import APIRouter
from schemas.event import BatchRequest, BatchResult, ClassificationResult, EventInput
from models import mitre_classifier as model

router = APIRouter(tags=["Threat Classifier"])


def load_model():
    model.load()


@router.post("/batch", response_model=BatchResult)
def classify_batch(request: BatchRequest) -> BatchResult:
    features_list = [_to_feature_dict(e) for e in request.events]
    predictions = model.predict(features_list)

    results = [
        ClassificationResult(
            event_id=event.event_id,
            tactic=pred["tactic"],
            technique=pred["technique"],
            tactic_id=pred["tactic_id"],
            technique_id=pred["technique_id"],
            confidence=pred["confidence"],
            mitre_url=pred["mitre_url"],
        )
        for event, pred in zip(request.events, predictions)
    ]

    return BatchResult(results=results, processed=len(results))


def _to_feature_dict(event: EventInput) -> dict:
    return {
        "severity_score": event.severity_score,
        "bytes_sent": event.bytes_sent,
        "bytes_received": event.bytes_received,
        "failed_logins": event.failed_logins,
        "unique_destinations": event.unique_destinations,
        "hour_of_day": event.hour_of_day,
        "destination_port": event.destination_port,
    }
