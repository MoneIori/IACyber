package com.iacyber.containerscanner.api.rest;

import com.iacyber.containerscanner.domain.ContainerFinding;
import com.iacyber.containerscanner.domain.ContainerTarget;
import com.iacyber.containerscanner.repository.ContainerFindingRepository;
import com.iacyber.containerscanner.repository.ContainerTargetRepository;
import com.iacyber.containerscanner.service.ContainerScanOrchestrator;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/container")
@RequiredArgsConstructor
public class ContainerScanController {

    private final ContainerScanOrchestrator orchestrator;
    private final ContainerTargetRepository targetRepository;
    private final ContainerFindingRepository findingRepository;

    // ─── Target management ────────────────────────────────────

    @PostMapping("/targets")
    @ResponseStatus(HttpStatus.CREATED)
    public ContainerTarget registerTarget(@RequestHeader("X-Tenant-ID") String tenantId,
                                          @Valid @RequestBody RegisterTargetRequest request) {
        ContainerTarget target = ContainerTarget.builder()
            .tenantId(tenantId)
            .name(request.name())
            .platform(request.platform())
            .endpoint(request.endpoint())
            .apiServer(request.apiServer())
            .credentialVaultPath(request.credentialVaultPath())
            .registryUrl(request.registryUrl())
            .cronExpression(request.cronExpression() != null ? request.cronExpression() : "0 0 2 * * *")
            .continuousRuntime(request.continuousRuntime() != null ? request.continuousRuntime() : true)
            .build();
        return targetRepository.save(target);
    }

    @GetMapping("/targets")
    public List<ContainerTarget> listTargets(@RequestHeader("X-Tenant-ID") String tenantId) {
        return targetRepository.findByTenantId(tenantId);
    }

    @DeleteMapping("/targets/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteTarget(@RequestHeader("X-Tenant-ID") String tenantId,
                             @PathVariable UUID id) {
        targetRepository.findByIdAndTenantId(id, tenantId)
            .ifPresent(targetRepository::delete);
    }

    // ─── Scan triggers ────────────────────────────────────────

    @PostMapping("/targets/{id}/scan")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ScanResponse triggerScan(@RequestHeader("X-Tenant-ID") String tenantId,
                                    @PathVariable UUID id) {
        List<ContainerFinding> findings = orchestrator.scanNow(id, tenantId);
        return new ScanResponse(findings.size(),
            (int) findings.stream().filter(f -> f.getSeverity() == ContainerFinding.Severity.CRITICAL).count(),
            (int) findings.stream().filter(f -> f.getSeverity() == ContainerFinding.Severity.HIGH).count());
    }

    // ─── Findings ─────────────────────────────────────────────

    @GetMapping("/findings")
    public Page<ContainerFinding> getFindings(
            @RequestHeader("X-Tenant-ID") String tenantId,
            @RequestParam(required = false) ContainerFinding.Severity severity,
            @RequestParam(required = false) ContainerFinding.Platform platform,
            @RequestParam(required = false) ContainerFinding.ScanType scanType,
            @RequestParam(required = false) ContainerFinding.FindingStatus status,
            Pageable pageable) {
        return findingRepository.findByFilters(tenantId, severity, platform, scanType, status, pageable);
    }

    @PatchMapping("/findings/{id}/status")
    public ContainerFinding updateFindingStatus(
            @RequestHeader("X-Tenant-ID") String tenantId,
            @PathVariable UUID id,
            @RequestBody StatusUpdateRequest request) {
        return findingRepository.findByIdAndTenantId(id, tenantId)
            .map(f -> {
                f.setStatus(request.status());
                return findingRepository.save(f);
            })
            .orElseThrow(() -> new IllegalArgumentException("Finding not found"));
    }

    // ─── DTOs ─────────────────────────────────────────────────

    public record RegisterTargetRequest(
        @NotBlank String name,
        @NotNull ContainerFinding.Platform platform,
        String endpoint,
        String apiServer,
        String credentialVaultPath,
        String registryUrl,
        String registryCredVaultPath,
        String cronExpression,
        Boolean continuousRuntime
    ) {}

    public record ScanResponse(int totalFindings, int critical, int high) {}

    public record StatusUpdateRequest(@NotNull ContainerFinding.FindingStatus status) {}
}
