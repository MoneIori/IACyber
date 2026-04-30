package com.iacyber.containerscanner.kafka.producer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iacyber.containerscanner.domain.ContainerFinding;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class FindingEventProducer {

    private static final String TOPIC = "iacyber.container.findings";
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    public void publish(ContainerFinding finding) {
        try {
            String payload = objectMapper.writeValueAsString(finding);
            kafkaTemplate.send(TOPIC, finding.getTenantId(), payload)
                .whenComplete((r, ex) -> {
                    if (ex != null) log.error("Failed to publish finding id={}", finding.getId(), ex);
                });
        } catch (Exception e) {
            log.error("Serialization failed for finding id={}", finding.getId(), e);
        }
    }
}
