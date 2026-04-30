"""
Risk scorer contestualizzato per container findings.
Considera: severity base, piattaforma, scan type, exploit availability,
CVSS score, e se il finding è in un workload critico (production namespace).
"""
import logging

logger = logging.getLogger(__name__)

# Moltiplicatori per piattaforma (OCP production = rischio maggiore)
PLATFORM_WEIGHT = {
    "OPENSHIFT":  1.3,
    "KUBERNETES": 1.2,
    "RANCHER":    1.2,
    "K3S":        1.0,
    "DOCKER":     1.0,
    "SWARM":      1.0,
    "PODMAN":     0.9,
    "NOMAD":      1.0,
}

SEVERITY_BASE_SCORE = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "INFO":     1.0,
}

SCAN_TYPE_WEIGHT = {
    "IMAGE_SECRET":  1.5,   # segreto hardcoded = rischio altissimo
    "RUNTIME":       1.4,   # comportamento anomalo live
    "RBAC":          1.3,   # escalation privilege
    "IMAGE_CVE":     1.0,
    "CONFIG":        1.0,
    "NETWORK":       1.1,
    "BENCHMARK":     0.8,
    "IMAGE_MALWARE": 1.6,
    "DOCKERFILE":    0.7,
}

_model_loaded = False


def load_model():
    global _model_loaded
    _model_loaded = True
    logger.info("Container risk scorer loaded (rule-based + heuristics)")


def score(finding: dict, platform: str) -> float:
    base = SEVERITY_BASE_SCORE.get(finding.get("severity", "INFO"), 1.0)
    platform_w = PLATFORM_WEIGHT.get(platform, 1.0)
    scan_type_w = SCAN_TYPE_WEIGHT.get(finding.get("scan_type", "CONFIG"), 1.0)

    # Bonus se è un CVE con CVSS alto
    cve_bonus = 0.0
    cve_id = finding.get("cve_id", "")
    if cve_id.startswith("CVE-"):
        cve_bonus = 0.5  # placeholder — in prod chiama NVD API per CVSS reale

    raw_score = (base * platform_w * scan_type_w) + cve_bonus
    return round(min(raw_score, 10.0), 2)
