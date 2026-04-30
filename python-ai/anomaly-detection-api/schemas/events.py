from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class EventFeatures(BaseModel):
    tenant_id: str
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    bytes_sent: Optional[int] = Field(default=0, ge=0)
    bytes_received: Optional[int] = Field(default=0, ge=0)
    duration_ms: Optional[int] = Field(default=0, ge=0)
    protocol: Optional[str] = None
    action: Optional[str] = None
    severity_score: float = Field(ge=0.0, le=10.0)
    hour_of_day: Optional[int] = Field(default=None, ge=0, le=23)
    day_of_week: Optional[int] = Field(default=None, ge=0, le=6)
    failed_logins_last_hour: Optional[int] = Field(default=0, ge=0)
    unique_destinations_last_hour: Optional[int] = Field(default=0, ge=0)


class AnomalyResult(BaseModel):
    event_id: str
    tenant_id: str
    is_anomaly: bool
    anomaly_score: float = Field(description="Score 0-1: più alto = più anomalo")
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: list[str] = Field(default_factory=list)


class BatchRequest(BaseModel):
    events: list[EventFeatures] = Field(min_length=1, max_length=1000)


class BatchResult(BaseModel):
    results: list[AnomalyResult]
    processed: int
    anomalies_found: int
