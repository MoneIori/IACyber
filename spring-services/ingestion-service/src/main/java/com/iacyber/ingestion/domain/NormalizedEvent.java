package com.iacyber.ingestion.domain;

import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Evento normalizzato secondo Elastic Common Schema (ECS).
 * Questo è il contratto pubblicato su Kafka verso SIEM e ML engine.
 */
@Builder
public record NormalizedEvent(
    UUID id,
    String tenantId,
    Instant timestamp,
    String sourceType,
    String sourceIp,
    String destinationIp,
    Integer sourcePort,
    Integer destinationPort,
    String protocol,
    String action,
    String outcome,          // success | failure | unknown
    String severity,         // low | medium | high | critical
    Double severityScore,    // 0.0 - 10.0
    String userId,
    String hostname,
    String process,
    String message,
    List<String> mitreTactics,
    List<String> mitreTechniques,
    Map<String, Object> labels,
    Map<String, Object> raw
) {}
