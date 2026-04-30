package com.iacyber.ingestion.api.rest;

import com.iacyber.ingestion.domain.RawEvent;
import com.iacyber.ingestion.service.IngestionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/ingest")
@RequiredArgsConstructor
public class IngestionController {

    private final IngestionService ingestionService;

    @PostMapping("/event")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void ingestSingle(@RequestHeader("X-Tenant-ID") String tenantId,
                             @Valid @RequestBody IngestRequest request,
                             HttpServletRequest httpRequest) {
        ingestionService.ingest(buildEvent(tenantId, request, httpRequest.getRemoteAddr()));
    }

    @PostMapping("/events/batch")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void ingestBatch(@RequestHeader("X-Tenant-ID") String tenantId,
                            @Valid @RequestBody List<IngestRequest> requests,
                            HttpServletRequest httpRequest) {
        String sourceIp = httpRequest.getRemoteAddr();
        requests.forEach(r -> ingestionService.ingest(buildEvent(tenantId, r, sourceIp)));
    }

    private RawEvent buildEvent(String tenantId, IngestRequest request, String sourceIp) {
        return RawEvent.builder()
            .tenantId(tenantId)
            .sourceType(request.sourceType())
            .rawPayload(request.payload())
            .sourceIp(sourceIp)
            .build();
    }

    public record IngestRequest(
        @NotBlank String sourceType,
        @NotBlank String payload
    ) {}
}
