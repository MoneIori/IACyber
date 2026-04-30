import os
import logging
from fastapi import APIRouter
from schemas.finding import EnrichRequest, EnrichedFinding
from models import risk_scorer

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Container Enrichment"])

# Remediation templates per scan type + severità
REMEDIATION_TEMPLATES: dict[str, dict] = {
    "IMAGE_CVE": {
        "steps": [
            "Identify the affected package: {affected_package}",
            "Check if a fixed version is available in the vulnerability advisory",
            "Update the base image or the specific package in your Dockerfile",
            "Rebuild and re-scan the image to verify the fix",
            "Update your Kubernetes Deployment / OCP DeploymentConfig with the new image tag",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/{cve_id}",
            "https://github.com/advisories?query={cve_id}",
        ],
    },
    "IMAGE_SECRET": {
        "steps": [
            "IMMEDIATE: Rotate the exposed secret/credential NOW",
            "Remove the secret from the Dockerfile, entrypoint, and all image layers",
            "Use Kubernetes Secrets or HashiCorp Vault to inject secrets at runtime",
            "Add secret scanning to your CI pipeline (Trivy, Trufflehog, Gitleaks)",
            "Audit git history for past exposure with: git log --all -S 'secret_value'",
            "Enable IRSA/Workload Identity instead of hardcoded cloud credentials",
        ],
        "references": [
            "https://kubernetes.io/docs/concepts/configuration/secret/",
            "https://developer.hashicorp.com/vault/docs/platform/k8s/injector",
        ],
    },
    "CONFIG": {
        "steps": [
            "Review the misconfiguration: {title}",
            "Apply the CIS Benchmark remediation for control {cis_control}",
            "Update the Kubernetes/OCP manifest to enforce the correct security context",
            "Use OPA/Gatekeeper or Kyverno to enforce this policy cluster-wide",
            "Re-scan after applying the fix to verify compliance",
        ],
        "references": [
            "https://www.cisecurity.org/benchmark/kubernetes",
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        ],
    },
    "RBAC": {
        "steps": [
            "Review the excessive permissions: {title}",
            "Apply principle of least privilege — remove unnecessary verbs/resources",
            "Replace ClusterRoleBinding with namespace-scoped RoleBinding where possible",
            "Audit all ServiceAccount token automounts and disable where not needed",
            "Use kubescape or rbac-police for ongoing RBAC monitoring",
        ],
        "references": [
            "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
            "https://github.com/PaloAltoNetworks/rbac-police",
        ],
    },
    "RUNTIME": {
        "steps": [
            "Investigate the Falco alert: {description}",
            "Check the process/syscall that triggered the rule",
            "Determine if the behavior is legitimate (tune Falco rule) or malicious (isolate pod)",
            "If malicious: cordon the node, preserve forensic evidence, escalate to incident",
            "Review container image for backdoors with: trivy image --scanners vuln,malware <image>",
        ],
        "references": [
            "https://falco.org/docs/rules/",
            "https://attack.mitre.org/matrices/enterprise/containers/",
        ],
    },
    "BENCHMARK": {
        "steps": [
            "Review the CIS Benchmark control: {cis_control}",
            "Apply the recommended configuration from the CIS Docker/K8s benchmark guide",
            "Automate compliance checking in your CI/CD pipeline",
            "Re-run the benchmark after applying fixes",
        ],
        "references": [
            "https://www.cisecurity.org/benchmark/docker",
            "https://www.cisecurity.org/benchmark/kubernetes",
        ],
    },
    "NETWORK": {
        "steps": [
            "Review exposed ports and services: {title}",
            "Apply Kubernetes NetworkPolicy to restrict ingress/egress",
            "Use service mesh (Istio/Linkerd) for mTLS between services",
            "Remove unnecessary NodePort/LoadBalancer service types",
            "Audit OCP routes and ensure TLS termination is enforced",
        ],
        "references": [
            "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
            "https://istio.io/latest/docs/concepts/security/",
        ],
    },
}

DEFAULT_REMEDIATION = {
    "steps": [
        "Review the finding details: {title}",
        "Consult the relevant security documentation for {scan_type}",
        "Apply the recommended fix and re-scan to verify",
    ],
    "references": [],
}


@router.post("/enrich", response_model=list[EnrichedFinding])
def enrich_findings(request: EnrichRequest) -> list[EnrichedFinding]:
    results = []

    for finding in request.findings:
        ai_score = risk_scorer.score(finding.model_dump(), request.platform.value)
        template = REMEDIATION_TEMPLATES.get(finding.scan_type.value, DEFAULT_REMEDIATION)

        ctx = {
            "title": finding.title,
            "cve_id": finding.cve_id or "N/A",
            "affected_package": finding.affected_package or "N/A",
            "scan_type": finding.scan_type.value,
            "description": finding.description[:200] if finding.description else "",
            "cis_control": finding.rule_id,
        }

        steps = [s.format(**ctx) for s in template["steps"]]
        refs  = [r.format(**ctx) for r in template["references"]]

        summary = (
            f"[{finding.severity.value}] {finding.title} detected on "
            f"{request.platform.value} target '{request.target_name}'. "
            f"AI risk score: {ai_score}/10. "
            f"Immediate action required: {steps[0] if steps else 'Review finding.'}"
        )

        results.append(EnrichedFinding(
            id=finding.id,
            ai_risk_score=ai_score,
            ai_remediation=summary,
            remediation_steps=steps,
            references=refs,
        ))

    return results
