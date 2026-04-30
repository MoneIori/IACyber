package com.iacyber.containerscanner.service;

import com.iacyber.containerscanner.domain.ContainerFinding;
import com.iacyber.containerscanner.domain.ContainerTarget;
import com.iacyber.containerscanner.kafka.producer.FindingEventProducer;
import com.iacyber.containerscanner.repository.ContainerFindingRepository;
import com.iacyber.containerscanner.repository.ContainerTargetRepository;
import com.iacyber.containerscanner.scanner.ContainerScanner;
import com.iacyber.containerscanner.scanner.ScanContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class ContainerScanOrchestrator {

    private final List<ContainerScanner> scanners;
    private final ContainerTargetRepository targetRepository;
    private final ContainerFindingRepository findingRepository;
    private final FindingEventProducer producer;
    private final ContainerAiEnrichmentService aiEnrichmentService;

    /**
     * Scan on-demand per un singolo target.
     */
    public List<ContainerFinding> scanNow(UUID targetId, String tenantId) {
        ContainerTarget target = targetRepository.findByIdAndTenantId(targetId, tenantId)
            .orElseThrow(() -> new IllegalArgumentException("Target not found"));

        return executeScan(target, ScanContext.fullScan(tenantId));
    }

    /**
     * Scheduled scan: ogni target ha il proprio cron, ma questo job
     * verifica ogni ora chi è in scadenza.
     */
    @Scheduled(fixedDelay = 3_600_000) // ogni ora
    public void scheduledScan() {
        List<ContainerTarget> due = targetRepository.findAllActiveAndDue(Instant.now());
        log.info("Scheduled scan: {} targets due", due.size());

        due.forEach(target -> {
            try {
                executeScan(target, ScanContext.fullScan(target.getTenantId()));
                target.setLastScan(Instant.now());
                targetRepository.save(target);
            } catch (Exception e) {
                log.error("Scheduled scan failed for target={}", target.getName(), e);
            }
        });
    }

    private List<ContainerFinding> executeScan(ContainerTarget target, ScanContext ctx) {
        log.info("Starting scan for target={} platform={} tenant={}",
                 target.getName(), target.getPlatform(), ctx.tenantId());

        List<ContainerFinding> allFindings = new ArrayList<>();

        // Esegui tutti gli scanner che supportano questa piattaforma
        for (ContainerScanner scanner : scanners) {
            if (!scanner.supportedPlatforms().contains(target.getPlatform())) continue;

            try {
                log.debug("Running scanner={} on target={}", scanner.getName(), target.getName());
                List<ContainerFinding> findings = scanner.scan(target, ctx);

                // AI enrichment: risk score contestualizzato + remediation
                List<ContainerFinding> enriched = aiEnrichmentService.enrich(findings, target);

                findingRepository.saveAll(enriched);
                enriched.forEach(producer::publish);
                allFindings.addAll(enriched);

                log.info("Scanner={} found={} findings on target={}",
                         scanner.getName(), findings.size(), target.getName());
            } catch (Exception e) {
                log.error("Scanner={} failed on target={} — {}", scanner.getName(), target.getName(), e.getMessage());
            }
        }

        log.info("Scan complete: target={} total_findings={}", target.getName(), allFindings.size());
        return allFindings;
    }
}
