package com.iacyber.containerscanner.scanner;

import com.iacyber.containerscanner.domain.ContainerFinding;
import com.iacyber.containerscanner.domain.ContainerTarget;

import java.util.List;
import java.util.Set;

/**
 * Interfaccia implementata da ogni scanner concreto.
 * Ogni tool (Trivy, Grype, Kubescape, ecc.) è un @Component separato.
 */
public interface ContainerScanner {

    String getName();

    Set<ContainerFinding.Platform> supportedPlatforms();

    Set<ContainerFinding.ScanType> supportedScanTypes();

    List<ContainerFinding> scan(ContainerTarget target, ScanContext context);
}
