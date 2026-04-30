package com.iacyber.containerscanner.repository;

import com.iacyber.containerscanner.domain.ContainerFinding;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface ContainerFindingRepository extends JpaRepository<ContainerFinding, UUID> {

    Optional<ContainerFinding> findByIdAndTenantId(UUID id, String tenantId);

    @Query("""
        SELECT f FROM ContainerFinding f
        WHERE f.tenantId = :tenantId
          AND (:severity IS NULL OR f.severity = :severity)
          AND (:platform IS NULL OR f.platform = :platform)
          AND (:scanType IS NULL OR f.scanType = :scanType)
          AND (:status   IS NULL OR f.status   = :status)
        ORDER BY f.detectedAt DESC
        """)
    Page<ContainerFinding> findByFilters(
        @Param("tenantId")  String tenantId,
        @Param("severity")  ContainerFinding.Severity severity,
        @Param("platform")  ContainerFinding.Platform platform,
        @Param("scanType")  ContainerFinding.ScanType scanType,
        @Param("status")    ContainerFinding.FindingStatus status,
        Pageable pageable
    );
}
