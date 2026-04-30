package com.iacyber.containerscanner.repository;

import com.iacyber.containerscanner.domain.ContainerTarget;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ContainerTargetRepository extends JpaRepository<ContainerTarget, UUID> {

    List<ContainerTarget> findByTenantId(String tenantId);

    Optional<ContainerTarget> findByIdAndTenantId(UUID id, String tenantId);

    @Query("""
        SELECT t FROM ContainerTarget t
        WHERE t.active = true
          AND (t.lastScan IS NULL OR t.lastScan < :cutoff)
        """)
    List<ContainerTarget> findAllActiveAndDue(@Param("cutoff") Instant cutoff);
}
