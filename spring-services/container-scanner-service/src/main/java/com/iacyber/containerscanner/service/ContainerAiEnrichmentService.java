package com.iacyber.containerscanner.service;

import com.iacyber.containerscanner.domain.ContainerFinding;
import com.iacyber.containerscanner.domain.ContainerTarget;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;
import java.util.Map;

/**
 * Chiama il Python container-ai-api per:
 * - Risk score contestualizzato (considera l'asset, la piattaforma, il tenant)
 * - Remediation step-by-step generata dall'LLM
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class ContainerAiEnrichmentService {

    private final WebClient.Builder webClientBuilder;

    @Value("${iacyber.ai.container-api-url:http://container-ai-api:9006}")
    private String containerAiApiUrl;

    @Value("${iacyber.ai.internal-token}")
    private String internalToken;

    public List<ContainerFinding> enrich(List<ContainerFinding> findings, ContainerTarget target) {
        if (findings.isEmpty()) return findings;

        try {
            WebClient client = webClientBuilder.baseUrl(containerAiApiUrl).build();

            // Chiama Python per batch enrichment
            List<Map<String, Object>> response = client.post()
                .uri("/api/v1/container/enrich")
                .header("X-Internal-Token", internalToken)
                .bodyValue(buildEnrichRequest(findings, target))
                .retrieve()
                .bodyToFlux(Map.class)
                .collectList()
                .block();

            if (response != null) {
                applyEnrichment(findings, response);
            }
        } catch (Exception e) {
            // AI enrichment non blocca il flusso — findings salvati senza AI
            log.warn("AI enrichment unavailable: {} — proceeding without it", e.getMessage());
        }

        return findings;
    }

    private Map<String, Object> buildEnrichRequest(List<ContainerFinding> findings,
                                                    ContainerTarget target) {
        return Map.of(
            "platform", target.getPlatform().name(),
            "target_name", target.getName(),
            "tenant_id", target.getTenantId(),
            "findings", findings.stream().map(f -> Map.of(
                "id", f.getId() != null ? f.getId().toString() : "",
                "rule_id", f.getRuleId(),
                "title", f.getTitle(),
                "description", f.getDescription() != null ? f.getDescription() : "",
                "severity", f.getSeverity().name(),
                "scan_type", f.getScanType().name(),
                "cve_id", f.getCveId() != null ? f.getCveId() : "",
                "affected_package", f.getAffectedPackage() != null ? f.getAffectedPackage() : ""
            )).toList()
        );
    }

    private void applyEnrichment(List<ContainerFinding> findings, List<Map<String, Object>> enriched) {
        for (int i = 0; i < Math.min(findings.size(), enriched.size()); i++) {
            Map<String, Object> ai = enriched.get(i);
            ContainerFinding finding = findings.get(i);

            if (ai.containsKey("ai_remediation")) {
                finding.setAiRemediation((String) ai.get("ai_remediation"));
            }
            if (ai.containsKey("ai_risk_score")) {
                finding.setAiRiskScore(((Number) ai.get("ai_risk_score")).doubleValue());
            }
        }
    }
}
