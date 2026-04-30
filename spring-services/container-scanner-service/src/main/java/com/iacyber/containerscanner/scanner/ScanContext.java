package com.iacyber.containerscanner.scanner;

import com.iacyber.containerscanner.domain.ContainerFinding;
import lombok.Builder;

import java.util.Set;

@Builder
public record ScanContext(
    String tenantId,
    Set<ContainerFinding.ScanType> requestedScanTypes,
    boolean fullScan
) {
    public static ScanContext fullScan(String tenantId) {
        return ScanContext.builder()
            .tenantId(tenantId)
            .requestedScanTypes(Set.of(ContainerFinding.ScanType.values()))
            .fullScan(true)
            .build();
    }
}
