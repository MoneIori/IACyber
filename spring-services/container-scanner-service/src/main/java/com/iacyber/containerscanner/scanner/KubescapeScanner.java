package com.iacyber.containerscanner.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iacyber.containerscanner.domain.ContainerFinding;
import com.iacyber.containerscanner.domain.ContainerTarget;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Kubescape: CIS Benchmark K8s + NSA-CISA + MITRE ATT&CK for containers.
 * Funziona su Kubernetes, OpenShift (OCP), K3s, Rancher.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class KubescapeScanner implements ContainerScanner {

    private static final int TIMEOUT_MINUTES = 10;

    // Framework supportati da Kubescape
    private static final List<String> FRAMEWORKS = List.of(
        "NSA", "MITRE", "CIS-K8S", "SOC2", "PCI-DSS", "GDPR"
    );

    private final ObjectMapper objectMapper;

    @Override
    public String getName() { return "kubescape"; }

    @Override
    public Set<ContainerFinding.Platform> supportedPlatforms() {
        return Set.of(
            ContainerFinding.Platform.KUBERNETES,
            ContainerFinding.Platform.OPENSHIFT,
            ContainerFinding.Platform.K3S,
            ContainerFinding.Platform.RANCHER
        );
    }

    @Override
    public Set<ContainerFinding.ScanType> supportedScanTypes() {
        return Set.of(
            ContainerFinding.ScanType.CONFIG,
            ContainerFinding.ScanType.RBAC,
            ContainerFinding.ScanType.BENCHMARK,
            ContainerFinding.ScanType.NETWORK
        );
    }

    @Override
    public List<ContainerFinding> scan(ContainerTarget target, ScanContext ctx) {
        List<ContainerFinding> findings = new ArrayList<>();

        for (String framework : FRAMEWORKS) {
            try {
                String json = runKubescape(target, framework);
                findings.addAll(parseKubescapeReport(json, target, ctx, framework));
            } catch (Exception e) {
                log.error("Kubescape scan failed for framework={} target={} — {}",
                          framework, target.getName(), e.getMessage());
            }
        }
        return findings;
    }

    private String runKubescape(ContainerTarget target, String framework)
            throws IOException, InterruptedException {

        List<String> args = new ArrayList<>(List.of(
            "kubescape", "scan", "framework", framework,
            "--format", "json",
            "--output", "/dev/stdout"
        ));

        // OCP usa le stesse credenziali K8s (kubeconfig con token OCP)
        if (target.getApiServer() != null) {
            args.addAll(List.of("--server", target.getApiServer()));
        }

        ProcessBuilder pb = new ProcessBuilder(args);
        pb.environment().put("KUBECONFIG", resolveKubeconfig(target));
        pb.redirectErrorStream(false);

        Process process = pb.start();
        boolean finished = process.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES);
        if (!finished) {
            process.destroyForcibly();
            throw new RuntimeException("Kubescape timed out");
        }

        return new String(process.getInputStream().readAllBytes());
    }

    private List<ContainerFinding> parseKubescapeReport(String json, ContainerTarget target,
                                                         ScanContext ctx, String framework) throws IOException {
        List<ContainerFinding> findings = new ArrayList<>();
        JsonNode root = objectMapper.readTree(json);

        for (JsonNode control : root.path("results")) {
            String status = control.path("status").path("status").asText();
            if ("passed".equalsIgnoreCase(status)) continue;

            String controlId = control.path("controlID").asText();
            String controlName = control.path("name").asText();
            double score = control.path("score").asDouble(0.0);

            for (JsonNode resource : control.path("rules").findValues("resourcesIDs")) {
                if (!resource.isArray()) continue;

                ContainerFinding.ScanType scanType = detectScanType(controlId, controlName);

                findings.add(ContainerFinding.builder()
                    .tenantId(ctx.tenantId())
                    .platform(target.getPlatform())
                    .scanType(scanType)
                    .target(target.getName())
                    .ruleId(framework + "-" + controlId)
                    .title(controlName)
                    .description(control.path("description").asText())
                    .severity(scoredToSeverity(score))
                    .cisControl(controlId)
                    .complianceFramework(framework)
                    .build());
            }
        }
        return findings;
    }

    private ContainerFinding.ScanType detectScanType(String controlId, String name) {
        String upper = name.toUpperCase();
        if (upper.contains("RBAC") || upper.contains("ROLE") || upper.contains("PERMISSION")) {
            return ContainerFinding.ScanType.RBAC;
        }
        if (upper.contains("NETWORK") || upper.contains("INGRESS") || upper.contains("EGRESS")) {
            return ContainerFinding.ScanType.NETWORK;
        }
        return ContainerFinding.ScanType.CONFIG;
    }

    private ContainerFinding.Severity scoredToSeverity(double score) {
        if (score >= 9.0) return ContainerFinding.Severity.CRITICAL;
        if (score >= 7.0) return ContainerFinding.Severity.HIGH;
        if (score >= 4.0) return ContainerFinding.Severity.MEDIUM;
        return ContainerFinding.Severity.LOW;
    }

    private String resolveKubeconfig(ContainerTarget target) {
        // In produzione recupera da Vault via credentialVaultPath
        // In dev usa il kubeconfig locale
        return System.getenv().getOrDefault("KUBECONFIG",
               System.getProperty("user.home") + "/.kube/config");
    }
}
