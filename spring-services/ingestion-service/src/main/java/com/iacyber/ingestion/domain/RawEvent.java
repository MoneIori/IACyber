package com.iacyber.ingestion.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "raw_events")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RawEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String sourceType;   // SYSLOG, CEF, JSON, WINDOWS_EVENT, CLOUD_TRAIL

    @Column(columnDefinition = "TEXT", nullable = false)
    private String rawPayload;

    @Column(nullable = false)
    private String sourceIp;

    @Column(nullable = false)
    @Builder.Default
    private Instant ingestedAt = Instant.now();

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private ProcessingStatus status = ProcessingStatus.RECEIVED;

    public enum ProcessingStatus {
        RECEIVED, NORMALIZED, PUBLISHED, ERROR
    }
}
