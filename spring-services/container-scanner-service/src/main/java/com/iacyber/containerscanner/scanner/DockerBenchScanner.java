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
 * Docker Bench Security: CIS Docker Benchmark per daemon Docker standalone.
 * Controlla: configurazione host, Docker daemon, immagini, container running,
 * orchestrazione, secrets, network.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class DockerBenchScanner implements ContainerScanner {

    private static final int TIMEOUT_MINUTES = 5;
    private final ObjectMapper objectMapper;

    @Override
    public String getName() { return "docker-bench-security"; }

    @Override
    public Set<ContainerFinding.Platform> supportedPlatforms() {
        return Set.of(ContainerFinding.Platform.DOCKER, ContainerFinding.Platform.SWARM);
    }

    @Override
    public Set<ContainerFinding.ScanType> supportedScanTypes() {
        return Set.of(
            ContainerFinding.ScanType.BENCHMARK,
            ContainerFinding.ScanType.CONFIG,
            ContainerFinding.ScanType.NETWORK
        );
    }

    @Override
    public List<ContainerFinding> scan(ContainerTarget target, ScanContext ctx) {
        try {
            String json = runDockerBench(target);
            return parseDockerBenchReport(json, target, ctx);
        } catch (Exception e) {
            log.error("Docker Bench failed for target={} — {}", target.getName(), e.getMessage());
            return List.of();
        }
    }

    private String runDockerBench(ContainerTarget target) throws IOException, InterruptedException {
        // Docker Bench gira come container privilegiato sul host target
        List<String> args = new ArrayList<>(List.of(
            "docker", "run", "--rm", "--net", "host", "--pid", "host",
            "--userns", "host",
            "-v", "/etc:/etc:ro",
            "-v", "/usr/bin/containerd:/usr/bin/containerd:ro",
            "-v", "/usr/bin/runc:/usr/bin/runc:ro",
            "-v", "/usr/lib/systemd:/usr/lib/systemd:ro",
            "-v", "/var/lib:/var/lib:ro",
            "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
            "--label", "docker_bench_security",
            "docker/docker-bench-security",
            "-l", "json"
        ));

        // Se target ha un endpoint remoto, usa DOCKER_HOST
        ProcessBuilder pb = new ProcessBuilder(args);
        if (target.getEndpoint() != null) {
            pb.environment().put("DOCKER_HOST", target.getEndpoint());
        }

        Process process = pb.start();
        boolean finished = process.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES);
        if (!finished) {
            process.destroyForcibly();
            throw new RuntimeException("Docker Bench timed out");
        }

        return new String(process.getInputStream().readAllBytes());
    }

    private List<ContainerFinding> parseDockerBenchReport(String json, ContainerTarget target,
                                                           ScanContext ctx) throws IOException {
        List<ContainerFinding> findings = new ArrayList<>();
        JsonNode root = objectMapper.readTree(json);

        for (JsonNode test : root.path("tests")) {
            String section = test.path("desc").asText();
            for (JsonNode result : test.path("results")) {
                String status = result.path("result").asText();
                if ("PASS".equalsIgnoreCase(status) || "INFO".equalsIgnoreCase(status)) continue;

                findings.add(ContainerFinding.builder()
                    .tenantId(ctx.tenantId())
                    .platform(target.getPlatform())
                    .scanType(ContainerFinding.ScanType.BENCHMARK)
                    .target(target.getName())
                    .ruleId("CIS-DOCKER-" + result.path("id").asText())
                    .title(result.path("desc").asText())
                    .description("[" + section + "] " + result.path("remediation").asText())
                    .severity("WARN".equalsIgnoreCase(status)
                        ? ContainerFinding.Severity.HIGH
                        : ContainerFinding.Severity.MEDIUM)
                    .cisControl(result.path("id").asText())
                    .complianceFramework("CIS-Docker")
                    .build());
            }
        }
        return findings;
    }
}
