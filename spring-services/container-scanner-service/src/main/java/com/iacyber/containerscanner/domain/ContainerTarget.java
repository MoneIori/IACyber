package com.iacyber.containerscanner.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Rappresenta un endpoint/cluster/registry che il cliente ha registrato
 * per la scansione continuativa.
 */
@Entity
@Table(name = "container_targets")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContainerTarget {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ContainerFinding.Platform platform;

    // ─── Connessione ─────────────────────────────────────────
    private String endpoint;            // Docker socket path o API URL
    private String apiServer;           // K8s/OCP API server URL
    private String credentialVaultPath; // path Vault per kubeconfig/token/certs

    // ─── Registry (per image scanning) ───────────────────────
    private String registryUrl;
    private String registryCredVaultPath;

    // ─── Scheduling ──────────────────────────────────────────
    @Builder.Default
    private String cronExpression = "0 0 2 * * *"; // ogni notte alle 02:00

    @Builder.Default
    private boolean continuousRuntime = true;        // Falco agent attivo

    @Builder.Default
    private boolean active = true;

    private Instant lastScan;

    @Builder.Default
    private Instant createdAt = Instant.now();
}
