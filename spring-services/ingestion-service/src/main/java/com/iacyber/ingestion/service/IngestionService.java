package com.iacyber.ingestion.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iacyber.ingestion.domain.NormalizedEvent;
import com.iacyber.ingestion.domain.RawEvent;
import com.iacyber.ingestion.normalizer.EventNormalizer;
import com.iacyber.ingestion.repository.RawEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class IngestionService {

    private static final String TOPIC_NORMALIZED = "iacyber.events.normalized";
    private static final String TOPIC_RAW        = "iacyber.events.raw";

    private final RawEventRepository rawEventRepository;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final List<EventNormalizer> normalizers;
    private final ObjectMapper objectMapper;

    @Transactional
    public void ingest(RawEvent event) {
        rawEventRepository.save(event);
        kafkaTemplate.send(TOPIC_RAW, event.getTenantId(), serialize(event));

        normalizers.stream()
            .filter(n -> n.supports(event.getSourceType()))
            .findFirst()
            .ifPresentOrElse(
                normalizer -> publishNormalized(event, normalizer.normalize(event)),
                () -> log.warn("No normalizer for sourceType={}", event.getSourceType())
            );
    }

    private void publishNormalized(RawEvent raw, NormalizedEvent normalized) {
        String payload = serialize(normalized);
        kafkaTemplate.send(TOPIC_NORMALIZED, normalized.tenantId(), payload)
            .whenComplete((result, ex) -> {
                if (ex != null) {
                    log.error("Failed to publish normalized event id={}", raw.getId(), ex);
                    raw.setStatus(RawEvent.ProcessingStatus.ERROR);
                } else {
                    raw.setStatus(RawEvent.ProcessingStatus.PUBLISHED);
                    log.debug("Published normalized event id={} tenant={}", normalized.id(), normalized.tenantId());
                }
                rawEventRepository.save(raw);
            });
    }

    private String serialize(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            throw new IllegalStateException("Serialization failed", e);
        }
    }
}
