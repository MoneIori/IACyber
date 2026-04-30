from pydantic import BaseModel, Field
from typing import Optional


class EventInput(BaseModel):
    event_id: str
    source_type: Optional[str] = None
    severity_score: float = Field(ge=0.0, le=10.0)
    action: Optional[str] = None
    protocol: Optional[str] = None
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)
    failed_logins: int = Field(default=0, ge=0)
    unique_destinations: int = Field(default=0, ge=0)
    hour_of_day: int = Field(default=12, ge=0, le=23)
    process_name: Optional[str] = None
    destination_port: int = Field(default=0, ge=0, le=65535)


class ClassificationResult(BaseModel):
    event_id: str
    tactic: str
    technique: str
    tactic_id: str
    technique_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_url: str


class BatchRequest(BaseModel):
    events: list[EventInput] = Field(min_length=1, max_length=1000)


class BatchResult(BaseModel):
    results: list[ClassificationResult]
    processed: int
