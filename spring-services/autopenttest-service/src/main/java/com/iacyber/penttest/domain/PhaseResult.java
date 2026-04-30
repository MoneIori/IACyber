package com.iacyber.penttest.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "pentest_phase_results")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PhaseResult {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id", nullable = false)
    private PentestSession session;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AttackPhase phase;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private PhaseStatus status = PhaseStatus.PENDING;

    // ─── Output grezzo dei tool ───────────────────────────────
    @Column(columnDefinition = "TEXT")
    private String rawOutput;           // output JSON/testo dai tool CLI

    // ─── Findings estratti ────────────────────────────────────
    @Column(columnDefinition = "TEXT")
    private String findingsJson;        // lista strutturata di finding per questa fase

    // ─── Narrative AI ─────────────────────────────────────────
    @Column(columnDefinition = "TEXT")
    private String aiNarrative;         // "Come hacker avrei..." — scritto dall'AI

    // ─── Timing ──────────────────────────────────────────────
    @Builder.Default
    private Instant startedAt = Instant.now();
    private Instant completedAt;
    private Long durationMs;

    // ─── MITRE mapping ────────────────────────────────────────
    private String mitreTactics;        // es. "TA0001,TA0002"
    private String mitreTechniques;     // es. "T1610,T1611"

    public enum AttackPhase {
        // Seguono l'ordine CEH / PTES
        RECONNAISSANCE,         // 1. Recon passivo: OSINT immagine, metadata, labels
        SCANNING,               // 2. Port scan, service discovery (nmap)
        ENUMERATION,            // 3. Servizi, versioni, API endpoints, env vars leakage
        VULNERABILITY_ANALYSIS, // 4. Match CVE, check exploit availability
        EXPLOITATION,           // 5. Exploit attivi (richiede aggressiveness HIGH/FULL)
        POST_EXPLOITATION,      // 6. Cosa può fare un attaccante dopo l'accesso
        LATERAL_MOVEMENT,       // 7. Pivot verso altri container/pod/namespace
        PRIVILEGE_ESCALATION,   // 8. Container escape, root, cluster-admin
        PERSISTENCE,            // 9. Backdoor, cron, DaemonSet malevolo
        COVERING_TRACKS,        // 10. Log deletion, audit evasion check
        REPORTING               // 11. Sintesi finale AI
    }

    public enum PhaseStatus {
        PENDING, RUNNING, COMPLETED, SKIPPED, FAILED
    }
}
