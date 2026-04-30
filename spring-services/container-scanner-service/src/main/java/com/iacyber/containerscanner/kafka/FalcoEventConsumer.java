package com.iacyber.containerscanner.kafka;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iacyber.containerscanner.domain.ContainerFinding;
import com.iacyber.containerscanner.repository.ContainerFindingRepository;
import com.iacyber.containerscanner.kafka.producer.FindingEventProducer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * Consuma gli eventi Falco dal topic Kafka.
 * Falco → webhook → ingestion-service → iacyber.falco.events → qui.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class FalcoEventConsumer {

    private final ContainerFindingRepository repository;
    private final FindingEventProducer producer;
    private final ObjectMapper objectMapper;

    @KafkaListener(topics = "iacyber.falco.events", groupId = "container-scanner-falco")
    public void onFalcoEvent(String message) {
        try {
            JsonNode event = objectMapper.readTree(message);
            ContainerFinding finding = convertFalcoEvent(event);
            repository.save(finding);
            producer.publish(finding);
            log.debug("Falco runtime finding saved: rule={} priority={}",
                      finding.getRuleId(), finding.getSeverity());
        } catch (Exception e) {
            log.error("Failed to process Falco event: {}", e.getMessage());
        }
    }

    private ContainerFinding convertFalcoEvent(JsonNode event) {
        // Falco output format: priority, rule, output, output_fields, time, hostname
        String priority = event.path("priority").asText("WARNING");
        String rule     = event.path("rule").asText("UNKNOWN");
        String output   = event.path("output").asText();
        String hostname = event.path("hostname").asText();
        String tenantId = event.path("output_fields").path("k8s.ns.name").asText("unknown");

        // Determina la piattaforma dall'output_fields
        ContainerFinding.Platform platform = detectPlatform(event);

        return ContainerFinding.builder()
            .tenantId(tenantId)
            .platform(platform)
            .scanType(ContainerFinding.ScanType.RUNTIME)
            .target(hostname)
            .namespace(event.path("output_fields").path("k8s.ns.name").asText())
            .workload(event.path("output_fields").path("k8s.pod.name").asText())
            .ruleId("FALCO-" + rule.toUpperCase().replace(" ", "_"))
            .title(rule)
            .description(output)
            .severity(mapFalcoPriority(priority))
            .build();
    }

    private ContainerFinding.Platform detectPlatform(JsonNode event) {
        JsonNode fields = event.path("output_fields");
        if (!fields.path("k8s.pod.name").isMissingNode()) {
            // Ha info K8s — potrebbe essere K8s o OCP
            String ns = fields.path("k8s.ns.name").asText("");
            // OCP ha namespace di sistema come openshift-*, openshift
            return ns.startsWith("openshift") ? ContainerFinding.Platform.OPENSHIFT
                                              : ContainerFinding.Platform.KUBERNETES;
        }
        return ContainerFinding.Platform.DOCKER;
    }

    private ContainerFinding.Severity mapFalcoPriority(String priority) {
        return switch (priority.toUpperCase()) {
            case "EMERGENCY", "ALERT", "CRITICAL" -> ContainerFinding.Severity.CRITICAL;
            case "ERROR"                           -> ContainerFinding.Severity.HIGH;
            case "WARNING"                         -> ContainerFinding.Severity.MEDIUM;
            case "NOTICE"                          -> ContainerFinding.Severity.LOW;
            default                                -> ContainerFinding.Severity.INFO;
        };
    }
}
