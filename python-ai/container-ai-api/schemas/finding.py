from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Platform(str, Enum):
    DOCKER     = "DOCKER"
    KUBERNETES = "KUBERNETES"
    OPENSHIFT  = "OPENSHIFT"
    SWARM      = "SWARM"
    PODMAN     = "PODMAN"
    K3S        = "K3S"
    RANCHER    = "RANCHER"
    NOMAD      = "NOMAD"


class ScanType(str, Enum):
    IMAGE_CVE    = "IMAGE_CVE"
    IMAGE_SECRET = "IMAGE_SECRET"
    IMAGE_MALWARE= "IMAGE_MALWARE"
    CONFIG       = "CONFIG"
    RUNTIME      = "RUNTIME"
    NETWORK      = "NETWORK"
    RBAC         = "RBAC"
    BENCHMARK    = "BENCHMARK"
    DOCKERFILE   = "DOCKERFILE"


class FindingInput(BaseModel):
    id: str
    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    scan_type: ScanType
    cve_id: str = ""
    affected_package: str = ""


class EnrichRequest(BaseModel):
    platform: Platform
    target_name: str
    tenant_id: str
    findings: list[FindingInput] = Field(min_length=1, max_length=500)


class EnrichedFinding(BaseModel):
    id: str
    ai_risk_score: float = Field(ge=0.0, le=10.0)
    ai_remediation: str
    remediation_steps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
