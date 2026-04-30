package com.iacyber.ingestion.repository;

import com.iacyber.ingestion.domain.RawEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RawEventRepository extends JpaRepository<RawEvent, UUID> {}
