package com.iacyber.ingestion.normalizer;

import com.iacyber.ingestion.domain.NormalizedEvent;
import com.iacyber.ingestion.domain.RawEvent;

public interface EventNormalizer {

    boolean supports(String sourceType);

    NormalizedEvent normalize(RawEvent raw);
}
