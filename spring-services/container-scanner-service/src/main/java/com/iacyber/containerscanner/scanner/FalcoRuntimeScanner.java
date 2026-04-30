package com.iacyber.containerscanner.scanner;

import com.iacyber.containerscanner.domain.ContainerFinding;
import com.iacyber.containerscanner.domain.ContainerTarget;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * Falco runtime scanner.
 *
 * Falco NON viene invocato come processo CLI — gira come DaemonSet sul cluster
 * (o come servizio systemd su Docker host) e invia eventi via webhook al nostro
 * ingestion-service, che li mette su Kafka.
 *
 * Questo component si occupa di:
 * 1. Generare la configurazione Falco personalizzata per il tenant
 * 2. Deployare il DaemonSet sul cluster del cliente (via K8s/OCP client)
 * 3. Leggere gli eventi Falco già normalizzati che arrivano da Kafka
 *    e convertirli in ContainerFinding
 */
@Component
@Slf4j
public class FalcoRuntimeScanner implements ContainerScanner {

    @Override
    public String getName() { return "falco-runtime"; }

    @Override
    public Set<ContainerFinding.Platform> supportedPlatforms() {
        return Set.of(
            ContainerFinding.Platform.DOCKER,
            ContainerFinding.Platform.KUBERNETES,
            ContainerFinding.Platform.OPENSHIFT,
            ContainerFinding.Platform.K3S,
            ContainerFinding.Platform.RANCHER,
            ContainerFinding.Platform.PODMAN
        );
    }

    @Override
    public Set<ContainerFinding.ScanType> supportedScanTypes() {
        return Set.of(ContainerFinding.ScanType.RUNTIME);
    }

    /**
     * Questo scanner non produce findings direttamente — li riceve da Kafka.
     * La pipeline è: Falco → webhook → ingestion-service → Kafka → siem-service.
     * Il FalcoKafkaConsumer (vedi sotto) converte gli eventi Kafka in ContainerFinding.
     */
    @Override
    public List<ContainerFinding> scan(ContainerTarget target, ScanContext ctx) {
        log.info("Falco runtime scan is event-driven — findings come from Kafka topic iacyber.falco.events");
        return List.of();
    }
}
