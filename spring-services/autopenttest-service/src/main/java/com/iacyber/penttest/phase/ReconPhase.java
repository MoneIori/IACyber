package com.iacyber.penttest.phase;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iacyber.penttest.domain.PhaseResult;
import com.iacyber.penttest.domain.PentestSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;

/**
 * FASE 1 — Reconnaissance
 *
 * Tecnica CEH: raccogliere quante più informazioni possibile
 * senza toccare il target direttamente (passive recon).
 *
 * Tool: Trivy image metadata, skopeo, crane, Docker inspect,
 *       kubectl get/describe, OCP oc describe
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class ReconPhase implements AttackPhaseExecutor {

    private final ObjectMapper objectMapper;
    private final ToolRunner toolRunner;

    @Override
    public PhaseResult.AttackPhase phase() {
        return PhaseResult.AttackPhase.RECONNAISSANCE;
    }

    @Override
    public PentestSession.AggressivenessLevel minimumAggressiveness() {
        return PentestSession.AggressivenessLevel.PASSIVE;
    }

    @Override
    public PhaseResult execute(PentestSession session) {
        Instant start = Instant.now();
        List<Map<String, Object>> findings = new ArrayList<>();
        StringBuilder rawOutput = new StringBuilder();

        // 1. Image metadata inspection
        if (session.getTargetRef() != null) {
            String imageInspect = toolRunner.run(
                "trivy", "image", "--format", "json",
                "--scanners", "", // solo metadata
                "--list-all-pkgs",
                session.getTargetRef()
            );
            rawOutput.append("=== IMAGE INSPECTION ===\n").append(imageInspect).append("\n");
            findings.addAll(extractImageMetadata(imageInspect, session));
        }

        // 2. K8s/OCP resource enumeration (passivo — solo describe)
        if (session.getTargetNamespace() != null) {
            String podDesc = toolRunner.run(
                "kubectl", "get", "pod", "-n", session.getTargetNamespace(),
                "-o", "json"
            );
            rawOutput.append("=== POD DESCRIPTOR ===\n").append(podDesc).append("\n");
            findings.addAll(extractK8sMetadata(podDesc, session));

            // Cerca secrets/configmap nei env vars (passivo)
            String envLeak = toolRunner.run(
                "kubectl", "get", "pod", "-n", session.getTargetNamespace(),
                "-o", "jsonpath={.items[*].spec.containers[*].env}"
            );
            rawOutput.append("=== ENV VARS (possible secret leak) ===\n").append(envLeak).append("\n");
            findings.addAll(checkEnvVarLeakage(envLeak, session));
        }

        // 3. Network policy check (un namespace senza NetworkPolicy è aperto)
        String netPolicies = toolRunner.run(
            "kubectl", "get", "networkpolicy",
            "-n", session.getTargetNamespace() != null ? session.getTargetNamespace() : "default",
            "-o", "json"
        );
        rawOutput.append("=== NETWORK POLICIES ===\n").append(netPolicies).append("\n");
        if (netPolicies.contains("\"items\": []") || netPolicies.isBlank()) {
            findings.add(Map.of(
                "type", "NO_NETWORK_POLICY",
                "severity", "HIGH",
                "description", "No NetworkPolicy found in namespace — all pod-to-pod traffic is allowed",
                "mitre", "TA0007 - Discovery, T1046 - Network Service Discovery",
                "ceh_note", "Attacker can freely scan and communicate with all pods in the namespace"
            ));
        }

        return PhaseResult.builder()
            .phase(PhaseResult.AttackPhase.RECONNAISSANCE)
            .status(PhaseResult.PhaseStatus.COMPLETED)
            .rawOutput(rawOutput.toString())
            .findingsJson(serialize(findings))
            .mitreTactics("TA0043")
            .mitreTechniques("T1595,T1592,T1589")
            .startedAt(start)
            .completedAt(Instant.now())
            .durationMs(Instant.now().toEpochMilli() - start.toEpochMilli())
            .build();
    }

    private List<Map<String, Object>> extractImageMetadata(String json, PentestSession session) {
        List<Map<String, Object>> findings = new ArrayList<>();
        try {
            var root = objectMapper.readTree(json);

            // Cerca labels con informazioni sensibili
            var labels = root.path("Metadata").path("ImageConfig").path("Labels");
            if (!labels.isMissingNode()) {
                labels.fieldNames().forEachRemaining(label -> {
                    if (label.toLowerCase().contains("token")
                     || label.toLowerCase().contains("password")
                     || label.toLowerCase().contains("secret")
                     || label.toLowerCase().contains("key")) {
                        findings.add(Map.of(
                            "type", "SENSITIVE_LABEL",
                            "severity", "CRITICAL",
                            "label", label,
                            "value", labels.path(label).asText(),
                            "mitre", "T1552.007 - Container API",
                            "ceh_note", "Sensitive data exposed in image labels — readable by anyone with Docker/K8s access"
                        ));
                    }
                });
            }

            // Verifica se l'immagine usa tag :latest (no pinning = supply chain risk)
            String ref = session.getTargetRef();
            if (ref != null && (ref.endsWith(":latest") || !ref.contains(":"))) {
                findings.add(Map.of(
                    "type", "UNPINNED_IMAGE",
                    "severity", "MEDIUM",
                    "description", "Image uses :latest tag — susceptible to supply chain attacks",
                    "mitre", "T1195.002 - Software Supply Chain",
                    "ceh_note", "Attacker could poison a future :latest pull with malicious code"
                ));
            }

            // Verifica presenza di package manager non rimossi (attack surface)
            var packages = root.path("Results");
            if (packages.isArray() && packages.size() > 200) {
                findings.add(Map.of(
                    "type", "BLOATED_IMAGE",
                    "severity", "LOW",
                    "package_count", packages.size(),
                    "description", "Image contains " + packages.size() + " packages — large attack surface",
                    "ceh_note", "Each package is a potential CVE vector. Use distroless or alpine base images."
                ));
            }

        } catch (Exception e) {
            log.warn("Image metadata parsing failed: {}", e.getMessage());
        }
        return findings;
    }

    private List<Map<String, Object>> extractK8sMetadata(String json, PentestSession session) {
        List<Map<String, Object>> findings = new ArrayList<>();
        try {
            var root = objectMapper.readTree(json);
            for (var pod : root.path("items")) {
                for (var container : pod.path("spec").path("containers")) {
                    // Privileged container
                    boolean privileged = container.path("securityContext")
                        .path("privileged").asBoolean(false);
                    if (privileged) {
                        findings.add(Map.of(
                            "type", "PRIVILEGED_CONTAINER",
                            "severity", "CRITICAL",
                            "container", container.path("name").asText(),
                            "mitre", "T1611 - Escape to Host",
                            "ceh_note", "Privileged container has full access to host kernel. " +
                                       "Trivial escape: mount /dev/sda1 and chroot to host filesystem."
                        ));
                    }

                    // hostPID / hostNetwork / hostIPC
                    boolean hostPid = pod.path("spec").path("hostPID").asBoolean(false);
                    boolean hostNet = pod.path("spec").path("hostNetwork").asBoolean(false);
                    if (hostPid || hostNet) {
                        findings.add(Map.of(
                            "type", hostPid ? "HOST_PID_SHARING" : "HOST_NETWORK_SHARING",
                            "severity", "CRITICAL",
                            "mitre", "T1611 - Escape to Host",
                            "ceh_note", "Direct host namespace access enables trivial container escape " +
                                       "and lateral movement to node-level resources."
                        ));
                    }

                    // runAsRoot / no securityContext
                    boolean runAsRoot = container.path("securityContext")
                        .path("runAsNonRoot").asBoolean(true) == false;
                    if (runAsRoot) {
                        findings.add(Map.of(
                            "type", "RUNS_AS_ROOT",
                            "severity", "HIGH",
                            "container", container.path("name").asText(),
                            "mitre", "T1078 - Valid Accounts",
                            "ceh_note", "Container running as root. Any RCE vulnerability gives immediate root."
                        ));
                    }
                }
            }
        } catch (Exception e) {
            log.warn("K8s metadata parsing failed: {}", e.getMessage());
        }
        return findings;
    }

    private List<Map<String, Object>> checkEnvVarLeakage(String envJson, PentestSession session) {
        List<Map<String, Object>> findings = new ArrayList<>();
        String upper = envJson.toUpperCase();

        List<String> sensitivePatterns = List.of(
            "PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY",
            "ACCESS_KEY", "DATABASE_URL", "JDBC", "MONGO_URI", "REDIS_URL"
        );

        for (String pattern : sensitivePatterns) {
            if (upper.contains(pattern)) {
                findings.add(Map.of(
                    "type", "ENV_SECRET_LEAK",
                    "severity", "CRITICAL",
                    "pattern", pattern,
                    "mitre", "T1552.007 - Container API",
                    "ceh_note", "Sensitive environment variable detected: " + pattern +
                               ". Accessible via 'kubectl exec -- env' or process /proc/<pid>/environ."
                ));
            }
        }
        return findings;
    }

    private String serialize(Object obj) {
        try { return objectMapper.writeValueAsString(obj); }
        catch (Exception e) { return "[]"; }
    }
}
