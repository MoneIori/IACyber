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
 * FASE 8 — Privilege Escalation & Container Escape
 *
 * CEH/OSCP technique: sfruttare misconfigurazioni per uscire dal container
 * e ottenere accesso al nodo host o al cluster.
 *
 * Tecniche controllate (check passivi — non eseguono exploit attivi in MEDIUM):
 * - Privileged container escape
 * - hostPath mount exploitation
 * - Service Account token abuse
 * - RBAC misconfiguration (wildcard verbs, cluster-admin)
 * - Writable /proc/sys/kernel/core_pattern (container escape)
 * - Docker socket mount
 * - CAP_SYS_ADMIN / CAP_NET_ADMIN capabilities
 * - Weak seccomp/AppArmor profile
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class PrivilegeEscalationPhase implements AttackPhaseExecutor {

    private final ObjectMapper objectMapper;
    private final ToolRunner toolRunner;

    @Override
    public PhaseResult.AttackPhase phase() {
        return PhaseResult.AttackPhase.PRIVILEGE_ESCALATION;
    }

    @Override
    public PentestSession.AggressivenessLevel minimumAggressiveness() {
        return PentestSession.AggressivenessLevel.MEDIUM;
    }

    @Override
    public PhaseResult execute(PentestSession session) {
        Instant start = Instant.now();
        List<Map<String, Object>> findings = new ArrayList<>();
        StringBuilder rawOutput = new StringBuilder();

        // 1. Service Account token check
        findings.addAll(checkServiceAccountPrivileges(session, rawOutput));

        // 2. Capability abuse check
        findings.addAll(checkDangerousCapabilities(session, rawOutput));

        // 3. hostPath mount check (accesso al filesystem host)
        findings.addAll(checkHostPathMounts(session, rawOutput));

        // 4. Docker socket mount
        findings.addAll(checkDockerSocketMount(session, rawOutput));

        // 5. RBAC wildcard check — via kubectl auth can-i
        findings.addAll(checkRbacEscalation(session, rawOutput));

        // 6. seccomp / AppArmor profile
        findings.addAll(checkSecurityProfiles(session, rawOutput));

        return PhaseResult.builder()
            .phase(PhaseResult.AttackPhase.PRIVILEGE_ESCALATION)
            .status(PhaseResult.PhaseStatus.COMPLETED)
            .rawOutput(rawOutput.toString())
            .findingsJson(serialize(findings))
            .mitreTactics("TA0004")
            .mitreTechniques("T1611,T1068,T1548,T1134")
            .startedAt(start)
            .completedAt(Instant.now())
            .durationMs(Instant.now().toEpochMilli() - start.toEpochMilli())
            .build();
    }

    private List<Map<String, Object>> checkServiceAccountPrivileges(PentestSession session, StringBuilder raw) {
        List<Map<String, Object>> findings = new ArrayList<>();

        // Verifica se il SA ha permessi cluster-admin o wildcard
        String[] dangerousChecks = {
            "kubectl auth can-i '*' '*' --all-namespaces",
            "kubectl auth can-i create clusterrolebinding --all-namespaces",
            "kubectl auth can-i create pods --all-namespaces",
            "kubectl auth can-i exec pod --all-namespaces",
            "kubectl auth can-i get secrets --all-namespaces"
        };

        for (String check : dangerousChecks) {
            String output = toolRunner.run(check.split(" "));
            raw.append(check).append(" → ").append(output.trim()).append("\n");

            if (output.trim().equalsIgnoreCase("yes")) {
                String permission = check.replace("kubectl auth can-i ", "").replace(" --all-namespaces", "");
                findings.add(Map.of(
                    "type", "EXCESSIVE_SA_PERMISSION",
                    "severity", "CRITICAL",
                    "permission", permission,
                    "mitre", "T1548 - Abuse Elevation Control Mechanism",
                    "ceh_exploit", buildSaExploitNote(permission),
                    "remediation", "Apply principle of least privilege. Scope RoleBinding to specific namespace and minimal verbs."
                ));
            }
        }

        // Verifica se il token SA è automountato e ha permessi alti
        String saToken = toolRunner.run(
            "kubectl", "get", "pod", "-n",
            session.getTargetNamespace() != null ? session.getTargetNamespace() : "default",
            "-o", "jsonpath={.items[*].spec.automountServiceAccountToken}"
        );
        raw.append("SA token automount: ").append(saToken).append("\n");

        if (saToken.contains("true") || !saToken.contains("false")) {
            findings.add(Map.of(
                "type", "SA_TOKEN_AUTOMOUNTED",
                "severity", "HIGH",
                "mitre", "T1528 - Steal Application Access Token",
                "ceh_exploit", "Token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token. " +
                              "From inside container: TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && " +
                              "kubectl --token=$TOKEN auth can-i --list",
                "remediation", "Set automountServiceAccountToken: false on pods that don't need K8s API access."
            ));
        }

        return findings;
    }

    private List<Map<String, Object>> checkDangerousCapabilities(PentestSession session, StringBuilder raw) {
        List<Map<String, Object>> findings = new ArrayList<>();

        String caps = toolRunner.run(
            "kubectl", "get", "pod", "-n",
            session.getTargetNamespace() != null ? session.getTargetNamespace() : "default",
            "-o", "jsonpath={.items[*].spec.containers[*].securityContext.capabilities.add}"
        );
        raw.append("=== CAPABILITIES ===\n").append(caps).append("\n");

        Map<String, String> dangerousCaps = Map.of(
            "SYS_ADMIN",     "T1611 - Escape to Host via mount/unshare. Exploit: unshare -m nsenter -t 1 -m -- bash",
            "SYS_PTRACE",    "T1055 - Process injection into host PIDs via ptrace()",
            "NET_ADMIN",     "T1040 - Network sniffing, ARP spoofing, iptables manipulation",
            "SYS_MODULE",    "T1611 - Load kernel modules → full host compromise",
            "DAC_OVERRIDE",  "T1548 - Bypass file permission checks",
            "CHOWN",         "T1548 - Change file ownership for privilege escalation",
            "SETUID",        "T1548 - Create setuid binaries for persistence"
        );

        for (Map.Entry<String, String> cap : dangerousCaps.entrySet()) {
            if (caps.contains(cap.getKey())) {
                findings.add(Map.of(
                    "type", "DANGEROUS_CAPABILITY",
                    "severity", "CRITICAL",
                    "capability", cap.getKey(),
                    "mitre", cap.getValue().split(" - ")[0].trim(),
                    "ceh_exploit", cap.getValue(),
                    "remediation", "Remove capability " + cap.getKey() + " from securityContext.capabilities.add. " +
                                  "Use seccomp profile RuntimeDefault or Localhost."
                ));
            }
        }
        return findings;
    }

    private List<Map<String, Object>> checkHostPathMounts(PentestSession session, StringBuilder raw) {
        List<Map<String, Object>> findings = new ArrayList<>();

        String volumes = toolRunner.run(
            "kubectl", "get", "pod", "-n",
            session.getTargetNamespace() != null ? session.getTargetNamespace() : "default",
            "-o", "jsonpath={.items[*].spec.volumes}"
        );
        raw.append("=== HOST PATH VOLUMES ===\n").append(volumes).append("\n");

        List<String> criticalHostPaths = List.of("/", "/etc", "/proc", "/sys", "/var/run/docker.sock",
                                                  "/var/lib/kubelet", "/run/containerd", "/root");
        for (String path : criticalHostPaths) {
            if (volumes.contains("\"path\":\"" + path + "\"") || volumes.contains("\"path\": \"" + path + "\"")) {
                findings.add(Map.of(
                    "type", "CRITICAL_HOSTPATH_MOUNT",
                    "severity", "CRITICAL",
                    "host_path", path,
                    "mitre", "T1611 - Escape to Host",
                    "ceh_exploit", buildHostPathExploit(path),
                    "remediation", "Remove hostPath volume. Use PersistentVolumeClaim or emptyDir instead."
                ));
            }
        }
        return findings;
    }

    private List<Map<String, Object>> checkDockerSocketMount(PentestSession session, StringBuilder raw) {
        List<Map<String, Object>> findings = new ArrayList<>();
        String volumes = toolRunner.run(
            "kubectl", "get", "pod", "-n",
            session.getTargetNamespace() != null ? session.getTargetNamespace() : "default",
            "-o", "jsonpath={.items[*].spec.volumes[*].hostPath.path}"
        );
        raw.append("=== DOCKER SOCKET CHECK ===\n").append(volumes).append("\n");

        if (volumes.contains("/var/run/docker.sock")) {
            findings.add(Map.of(
                "type", "DOCKER_SOCKET_MOUNTED",
                "severity", "CRITICAL",
                "mitre", "T1611 - Escape to Host",
                "ceh_exploit", "Docker socket mounted inside container. " +
                              "Trivial full host escape: docker run -it --rm --privileged --pid=host " +
                              "-v /:/host alpine chroot /host",
                "remediation", "Never mount /var/run/docker.sock. Use purpose-built tools (Kaniko, Buildah) for in-cluster builds."
            ));
        }
        return findings;
    }

    private List<Map<String, Object>> checkRbacEscalation(PentestSession session, StringBuilder raw) {
        List<Map<String, Object>> findings = new ArrayList<>();

        // Cerca ClusterRoleBinding con wildcard
        String crbs = toolRunner.run(
            "kubectl", "get", "clusterrolebinding", "-o",
            "jsonpath={range .items[*]}{.metadata.name}{\" \"}{.roleRef.name}{\"\\n\"}{end}"
        );
        raw.append("=== CLUSTER ROLE BINDINGS ===\n").append(crbs).append("\n");

        if (crbs.contains("cluster-admin")) {
            findings.add(Map.of(
                "type", "CLUSTER_ADMIN_BINDING",
                "severity", "CRITICAL",
                "mitre", "T1078.004 - Cloud Accounts",
                "ceh_exploit", "cluster-admin ClusterRoleBinding found. " +
                              "From compromised pod with this SA: full cluster takeover. " +
                              "Can create new cluster-admin users, access all secrets, deploy DaemonSets.",
                "remediation", "Audit all cluster-admin bindings. Use namespace-scoped roles. " +
                              "Apply time-limited access with tools like Teleport."
            ));
        }
        return findings;
    }

    private List<Map<String, Object>> checkSecurityProfiles(PentestSession session, StringBuilder raw) {
        List<Map<String, Object>> findings = new ArrayList<>();
        String pods = toolRunner.run(
            "kubectl", "get", "pod", "-n",
            session.getTargetNamespace() != null ? session.getTargetNamespace() : "default",
            "-o", "jsonpath={.items[*].spec.securityContext}"
        );
        raw.append("=== SECURITY CONTEXT ===\n").append(pods).append("\n");

        if (!pods.contains("seccompProfile") && !pods.contains("appArmor")) {
            findings.add(Map.of(
                "type", "NO_SECCOMP_APPARMOR",
                "severity", "HIGH",
                "mitre", "T1611 - Escape to Host",
                "ceh_exploit", "No seccomp/AppArmor profile. All syscalls available to container. " +
                              "Enables kernel exploit techniques (Dirty COW, etc.) if running vulnerable kernel.",
                "remediation", "Apply seccomp: RuntimeDefault in pod securityContext. " +
                              "Enable AppArmor profiles via annotations."
            ));
        }
        return findings;
    }

    private String buildSaExploitNote(String permission) {
        if (permission.contains("'*' '*'")) {
            return "Full cluster-admin via SA token. From inside pod: kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) get secrets -A";
        }
        if (permission.contains("create clusterrolebinding")) {
            return "Can create new cluster-admin binding for attacker-controlled SA.";
        }
        if (permission.contains("exec pod")) {
            return "Can exec into any pod in cluster — pivot to other workloads.";
        }
        return "Excessive permission allows further cluster access.";
    }

    private String buildHostPathExploit(String path) {
        return switch (path) {
            case "/"    -> "Root filesystem mounted. chroot /mounted-host → full host access.";
            case "/etc" -> "Read /etc/shadow, /etc/crontab. Modify /etc/sudoers for persistence.";
            case "/proc"-> "Access host /proc/1/root → escape container namespace.";
            case "/var/run/docker.sock" -> "Docker socket: deploy privileged container → host escape.";
            case "/var/lib/kubelet" -> "Access kubelet config, certificates, pod specs, credentials.";
            default     -> "HostPath " + path + " mounted — investigate writable access.";
        };
    }

    private String serialize(Object obj) {
        try { return objectMapper.writeValueAsString(obj); }
        catch (Exception e) { return "[]"; }
    }
}
