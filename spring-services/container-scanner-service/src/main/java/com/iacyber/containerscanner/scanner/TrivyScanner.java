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
 * Trivy scanner: immagini Docker (CVE + secret), K8s cluster, config files.
 * Supporta Docker, Kubernetes, OpenShift, K3s, Rancher.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class TrivyScanner implements ContainerScanner {

    private static final int TIMEOUT_MINUTES = 15;
    private final ObjectMapper objectMapper;

    @Override
    public String getName() { return "trivy"; }

    @Override
    public Set<ContainerFinding.Platform> supportedPlatforms() {
        return Set.of(
            ContainerFinding.Platform.DOCKER,
            ContainerFinding.Platform.KUBERNETES,
            ContainerFinding.Platform.OPENSHIFT,
            ContainerFinding.Platform.K3S,
            ContainerFinding.Platform.RANCHER,
            ContainerFinding.Platform.PODMAN
        );
    }

    @Override
    public Set<ContainerFinding.ScanType> supportedScanTypes() {
        return Set.of(
            ContainerFinding.ScanType.IMAGE_CVE,
            ContainerFinding.ScanType.IMAGE_SECRET,
            ContainerFinding.ScanType.CONFIG,
            ContainerFinding.ScanType.BENCHMARK
        );
    }

    @Override
    public List<ContainerFinding> scan(ContainerTarget target, ScanContext ctx) {
        List<ContainerFinding> findings = new ArrayList<>();

        if (ctx.requestedScanTypes().contains(ContainerFinding.ScanType.IMAGE_CVE)
            || ctx.requestedScanTypes().contains(ContainerFinding.ScanType.IMAGE_SECRET)) {
            findings.addAll(scanImages(target, ctx));
        }

        if (ctx.requestedScanTypes().contains(ContainerFinding.ScanType.CONFIG)
            && isClusterPlatform(target.getPlatform())) {
            findings.addAll(scanClusterConfig(target, ctx));
        }

        return findings;
    }

    // ─── Image scanning ──────────────────────────────────────

    private List<ContainerFinding> scanImages(ContainerTarget target, ScanContext ctx) {
        List<String> images = resolveImages(target);
        List<ContainerFinding> findings = new ArrayList<>();

        for (String imageRef : images) {
            try {
                String json = runTrivy(buildImageArgs(imageRef, target));
                findings.addAll(parseTrivyImageReport(json, imageRef, target, ctx));
            } catch (Exception e) {
                log.error("Trivy image scan failed for {} — {}", imageRef, e.getMessage());
            }
        }
        return findings;
    }

    private List<String> buildImageArgs(String imageRef, ContainerTarget target) {
        List<String> args = new ArrayList<>(List.of(
            "trivy", "image",
            "--format", "json",
            "--scanners", "vuln,secret",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW"
        ));

        if (target.getRegistryUrl() != null) {
            args.addAll(List.of("--registry", target.getRegistryUrl()));
        }

        args.add(imageRef);
        return args;
    }

    // ─── Cluster config scanning ──────────────────────────────

    private List<ContainerFinding> scanClusterConfig(ContainerTarget target, ScanContext ctx) {
        try {
            List<String> args = buildClusterArgs(target);
            String json = runTrivy(args);
            return parseTrivyClusterReport(json, target, ctx);
        } catch (Exception e) {
            log.error("Trivy cluster scan failed for {} — {}", target.getName(), e.getMessage());
            return List.of();
        }
    }

    private List<String> buildClusterArgs(ContainerTarget target) {
        List<String> args = new ArrayList<>(List.of(
            "trivy", "k8s",
            "--format", "json",
            "--scanners", "vuln,misconfig,secret,rbac",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW"
        ));

        // OCP usa lo stesso API server K8s — Trivy lo gestisce nativamente
        if (target.getApiServer() != null) {
            args.addAll(List.of("--server", target.getApiServer()));
        }

        args.add("--all-namespaces");
        return args;
    }

    // ─── Parse risultati immagine ─────────────────────────────

    private List<ContainerFinding> parseTrivyImageReport(String json, String imageRef,
                                                          ContainerTarget target, ScanContext ctx) throws IOException {
        List<ContainerFinding> findings = new ArrayList<>();
        JsonNode root = objectMapper.readTree(json);
        JsonNode results = root.path("Results");

        if (!results.isArray()) return findings;

        for (JsonNode result : results) {
            // CVE vulnerabilities
            for (JsonNode vuln : result.path("Vulnerabilities")) {
                findings.add(ContainerFinding.builder()
                    .tenantId(ctx.tenantId())
                    .platform(target.getPlatform())
                    .scanType(ContainerFinding.ScanType.IMAGE_CVE)
                    .target(imageRef)
                    .ruleId(vuln.path("VulnerabilityID").asText("UNKNOWN"))
                    .title(vuln.path("Title").asText(vuln.path("VulnerabilityID").asText()))
                    .description(vuln.path("Description").asText())
                    .severity(mapSeverity(vuln.path("Severity").asText()))
                    .cvssScore(vuln.path("CVSS").path("nvd").path("V3Score").asDouble(0.0))
                    .cveId(vuln.path("VulnerabilityID").asText())
                    .affectedPackage(vuln.path("PkgName").asText())
                    .affectedVersion(vuln.path("InstalledVersion").asText())
                    .fixedVersion(vuln.path("FixedVersion").asText())
                    .build());
            }

            // Secrets
            for (JsonNode secret : result.path("Secrets")) {
                findings.add(ContainerFinding.builder()
                    .tenantId(ctx.tenantId())
                    .platform(target.getPlatform())
                    .scanType(ContainerFinding.ScanType.IMAGE_SECRET)
                    .target(imageRef)
                    .ruleId("SECRET-" + secret.path("RuleID").asText())
                    .title("Hardcoded secret: " + secret.path("Category").asText())
                    .description("Secret found at: " + secret.path("Match").asText())
                    .severity(ContainerFinding.Severity.CRITICAL)
                    .build());
            }
        }
        return findings;
    }

    // ─── Parse risultati cluster ──────────────────────────────

    private List<ContainerFinding> parseTrivyClusterReport(String json, ContainerTarget target,
                                                            ScanContext ctx) throws IOException {
        List<ContainerFinding> findings = new ArrayList<>();
        JsonNode root = objectMapper.readTree(json);

        for (JsonNode resource : root.path("Resources")) {
            String namespace = resource.path("Namespace").asText();
            String name = resource.path("Name").asText();
            String kind = resource.path("Kind").asText();

            for (JsonNode result : resource.path("Results")) {
                for (JsonNode misconfig : result.path("Misconfigurations")) {
                    findings.add(ContainerFinding.builder()
                        .tenantId(ctx.tenantId())
                        .platform(target.getPlatform())
                        .scanType(ContainerFinding.ScanType.CONFIG)
                        .target(target.getName())
                        .namespace(namespace)
                        .workload(kind + "/" + name)
                        .ruleId(misconfig.path("ID").asText())
                        .title(misconfig.path("Title").asText())
                        .description(misconfig.path("Description").asText())
                        .severity(mapSeverity(misconfig.path("Severity").asText()))
                        .cisControl(misconfig.path("CauseMetadata").path("Code").asText())
                        .complianceFramework("CIS")
                        .build());
                }
            }
        }
        return findings;
    }

    // ─── Utilità ─────────────────────────────────────────────

    private String runTrivy(List<String> args) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(args);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        boolean finished = process.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES);
        if (!finished) {
            process.destroyForcibly();
            throw new RuntimeException("Trivy timed out after " + TIMEOUT_MINUTES + " minutes");
        }

        return new String(process.getInputStream().readAllBytes());
    }

    private List<String> resolveImages(ContainerTarget target) {
        if (target.getPlatform() == ContainerFinding.Platform.DOCKER) {
            return resolveDockerImages(target);
        }
        return List.of(); // per K8s/OCP usa scanClusterConfig che include le immagini dei pod
    }

    private List<String> resolveDockerImages(ContainerTarget target) {
        // In produzione: chiama Docker API per listare le immagini del daemon
        // Per ora restituisce lista vuota — l'integrazione Docker viene nel DockerPlatformConnector
        return List.of();
    }

    private boolean isClusterPlatform(ContainerFinding.Platform platform) {
        return switch (platform) {
            case KUBERNETES, OPENSHIFT, K3S, RANCHER -> true;
            default -> false;
        };
    }

    private ContainerFinding.Severity mapSeverity(String trivySeverity) {
        return switch (trivySeverity.toUpperCase()) {
            case "CRITICAL" -> ContainerFinding.Severity.CRITICAL;
            case "HIGH"     -> ContainerFinding.Severity.HIGH;
            case "MEDIUM"   -> ContainerFinding.Severity.MEDIUM;
            case "LOW"      -> ContainerFinding.Severity.LOW;
            default         -> ContainerFinding.Severity.INFO;
        };
    }
}
