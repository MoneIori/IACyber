package com.iacyber.containerscanner.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Finding normalizzato da qualsiasi scanner/piattaforma.
 * Docker, K8s, OCP, Swarm → stesso modello.
 */
@Entity
@Table(name = "container_findings")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContainerFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String tenantId;

    // ─── Sorgente ────────────────────────────────────────────
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Platform platform;          // DOCKER, KUBERNETES, OPENSHIFT, SWARM, PODMAN, K3S, RANCHER

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScanType scanType;          // IMAGE, CONFIG, RUNTIME, NETWORK, SECRET, RBAC, BENCHMARK

    @Column(nullable = false)
    private String target;              // image ref, namespace/pod, node name, ecc.

    private String clusterId;           // null se Docker standalone
    private String namespace;
    private String workload;            // Deployment, DaemonSet, Pod, ecc.

    // ─── Finding ─────────────────────────────────────────────
    @Column(nullable = false)
    private String ruleId;              // CVE-2024-1234 | CIS-K8S-1.1.1 | FALCO-001 | ecc.

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;          // CRITICAL, HIGH, MEDIUM, LOW, INFO

    private Double cvssScore;

    private String cveId;
    private String cweId;
    private String affectedPackage;
    private String affectedVersion;
    private String fixedVersion;

    // ─── Misconfiguration / Benchmark ────────────────────────
    private String cisControl;          // es. "CIS K8s 1.1.1"
    private String complianceFramework; // CIS, NSA-CISA, MITRE, PCI-DSS

    // ─── AI Remediation (compilato da Python AI) ─────────────
    @Column(columnDefinition = "TEXT")
    private String aiRemediation;

    private Double aiRiskScore;         // 0.0 - 10.0 contesto-aware

    // ─── Stato ───────────────────────────────────────────────
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private FindingStatus status = FindingStatus.OPEN;

    @Builder.Default
    private Instant detectedAt = Instant.now();
    private Instant resolvedAt;

    // ─── Enums ───────────────────────────────────────────────
    public enum Platform {
        DOCKER, KUBERNETES, OPENSHIFT, SWARM, PODMAN, K3S, RANCHER, NOMAD
    }

    public enum ScanType {
        IMAGE_CVE,       // CVE in OS packages e librerie dell'immagine
        IMAGE_SECRET,    // Segreti hardcoded nell'immagine (token, password)
        IMAGE_MALWARE,   // Malware/backdoor nell'immagine
        CONFIG,          // Misconfigurazioni (privileged, root user, ecc.)
        RUNTIME,         // Comportamenti anomali a runtime (Falco)
        NETWORK,         // Porte esposte, network policy mancanti
        RBAC,            // Permessi eccessivi su K8s/OCP
        BENCHMARK,       // CIS Benchmark Docker/K8s
        DOCKERFILE       // Analisi statica Dockerfile (Hadolint)
    }

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW, INFO
    }

    public enum FindingStatus {
        OPEN, ACKNOWLEDGED, FIXED, WONT_FIX, FALSE_POSITIVE
    }
}
