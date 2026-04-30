package com.iacyber.ingestion.normalizer;

import com.iacyber.ingestion.domain.NormalizedEvent;
import com.iacyber.ingestion.domain.RawEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class SyslogNormalizer implements EventNormalizer {

    // RFC 5424: <priority>version timestamp hostname app-name procid msgid msg
    private static final Pattern SYSLOG_PATTERN = Pattern.compile(
        "<(\\d+)>\\d+ (\\S+) (\\S+) (\\S+) (\\S+) (\\S+) (.+)"
    );

    @Override
    public boolean supports(String sourceType) {
        return "SYSLOG".equalsIgnoreCase(sourceType);
    }

    @Override
    public NormalizedEvent normalize(RawEvent raw) {
        Matcher m = SYSLOG_PATTERN.matcher(raw.getRawPayload().trim());

        if (!m.matches()) {
            return buildUnparsed(raw);
        }

        int priority = Integer.parseInt(m.group(1));
        int severity = priority & 0x07;           // 3 LSB
        String timestamp = m.group(2);
        String hostname = m.group(3);
        String appName = m.group(4);
        String message = m.group(7);

        return NormalizedEvent.builder()
            .id(UUID.randomUUID())
            .tenantId(raw.getTenantId())
            .timestamp(parseTimestamp(timestamp))
            .sourceType("SYSLOG")
            .sourceIp(raw.getSourceIp())
            .hostname(hostname)
            .process(appName)
            .message(message)
            .severity(mapSeverity(severity))
            .severityScore(mapSeverityScore(severity))
            .outcome("unknown")
            .mitreTactics(Collections.emptyList())
            .mitreTechniques(Collections.emptyList())
            .labels(Map.of("app", appName))
            .raw(Map.of("original", raw.getRawPayload()))
            .build();
    }

    private NormalizedEvent buildUnparsed(RawEvent raw) {
        return NormalizedEvent.builder()
            .id(UUID.randomUUID())
            .tenantId(raw.getTenantId())
            .timestamp(raw.getIngestedAt())
            .sourceType("SYSLOG")
            .sourceIp(raw.getSourceIp())
            .message(raw.getRawPayload())
            .severity("low")
            .severityScore(0.0)
            .outcome("unknown")
            .mitreTactics(Collections.emptyList())
            .mitreTechniques(Collections.emptyList())
            .labels(Collections.emptyMap())
            .raw(Map.of("original", raw.getRawPayload(), "parse_error", "true"))
            .build();
    }

    private Instant parseTimestamp(String ts) {
        try {
            return Instant.parse(ts);
        } catch (Exception e) {
            return Instant.now();
        }
    }

    private String mapSeverity(int syslogSeverity) {
        return switch (syslogSeverity) {
            case 0, 1, 2 -> "critical";
            case 3       -> "high";
            case 4       -> "medium";
            default      -> "low";
        };
    }

    private double mapSeverityScore(int syslogSeverity) {
        return switch (syslogSeverity) {
            case 0 -> 10.0;
            case 1 -> 9.0;
            case 2 -> 8.0;
            case 3 -> 7.0;
            case 4 -> 5.0;
            case 5 -> 3.0;
            default -> 1.0;
        };
    }
}
