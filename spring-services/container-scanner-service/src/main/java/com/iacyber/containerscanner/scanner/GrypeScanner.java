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
 * Grype: scanner CVE su immagini e SBOM.
 * Complementare a Trivy — database CVE diverso (GitHub Advisory + NVD + OSV).
 * Ottimo per linguaggi: Java, Node, Python, Go, Ruby, Rust.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class GrypeScanner implements ContainerScanner {

    private static final int TIMEOUT_MINUTES = 10;
    private final ObjectMapper objectMapper;

    @Override
    public String getName() { return "grype"; }

    @Override
    public Set<ContainerFinding.Platform> supportedPlatforms() {
        return Set.of(ContainerFinding.Platform.values()); // funziona su qualsiasi immagine
    }

    @Override
    public Set<ContainerFinding.ScanType> supportedScanTypes() {
        return Set.of(ContainerFinding.ScanType.IMAGE_CVE);
    }

    @Override
    public List<ContainerFinding> scan(ContainerTarget target, ScanContext ctx) {
        if (!ctx.requestedScanTypes().contains(ContainerFinding.ScanType.IMAGE_CVE)) {
            return List.of();
        }

        List<ContainerFinding> findings = new ArrayList<>();

        // Grype può scansionare: image ref, directory, SBOM file, OCI archive
        String scanTarget = target.getRegistryUrl() != null
            ? "registry:" + target.getRegistryUrl()
            : target.getEndpoint();

        if (scanTarget == null) return findings;

        try {
            String json = runGrype(scanTarget, target);
            findings.addAll(parseGrypeReport(json, target, ctx));
        } catch (Exception e) {
            log.error("Grype scan failed for target={} — {}", target.getName(), e.getMessage());
        }
        return findings;
    }

    private String runGrype(String scanTarget, ContainerTarget target)
            throws IOException, InterruptedException {
        List<String> args = new ArrayList<>(List.of(
            "grype", scanTarget,
            "--output", "json",
            "--fail-on", "none",        // non fallisce, restituisce sempre JSON
            "--only-fixed"              // mostra solo CVE con fix disponibile (cambia in prod)
        ));

        ProcessBuilder pb = new ProcessBuilder(args);
        if (target.getEndpoint() != null) {
            pb.environment().put("DOCKER_HOST", target.getEndpoint());
        }

        Process process = pb.start();
        boolean finished = process.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES);
        if (!finished) {
            process.destroyForcibly();
            throw new RuntimeException("Grype timed out");
        }

        return new String(process.getInputStream().readAllBytes());
    }

    private List<ContainerFinding> parseGrypeReport(String json, ContainerTarget target,
                                                     ScanContext ctx) throws IOException {
        List<ContainerFinding> findings = new ArrayList<>();
        JsonNode root = objectMapper.readTree(json);

        for (JsonNode match : root.path("matches")) {
            JsonNode vuln = match.path("vulnerability");
            JsonNode artifact = match.path("artifact");

            String cveId = vuln.path("id").asText();
            double cvss = 0.0;
            for (JsonNode cvssNode : vuln.path("cvss")) {
                double v = cvssNode.path("metrics").path("baseScore").asDouble(0.0);
                if (v > cvss) cvss = v;
            }

            findings.add(ContainerFinding.builder()
                .tenantId(ctx.tenantId())
                .platform(target.getPlatform())
                .scanType(ContainerFinding.ScanType.IMAGE_CVE)
                .target(target.getName())
                .ruleId("GRYPE-" + cveId)
                .title(vuln.path("description").asText(cveId).substring(0, Math.min(200,
                       vuln.path("description").asText(cveId).length())))
                .description(vuln.path("description").asText())
                .severity(mapSeverity(vuln.path("severity").asText()))
                .cvssScore(cvss)
                .cveId(cveId)
                .affectedPackage(artifact.path("name").asText())
                .affectedVersion(artifact.path("version").asText())
                .fixedVersion(vuln.path("fix").path("versions").path(0).asText())
                .build());
        }
        return findings;
    }

    private ContainerFinding.Severity mapSeverity(String s) {
        return switch (s.toUpperCase()) {
            case "CRITICAL" -> ContainerFinding.Severity.CRITICAL;
            case "HIGH"     -> ContainerFinding.Severity.HIGH;
            case "MEDIUM"   -> ContainerFinding.Severity.MEDIUM;
            case "LOW"      -> ContainerFinding.Severity.LOW;
            default         -> ContainerFinding.Severity.INFO;
        };
    }
}
