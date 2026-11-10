package com.siem.alarm.threat;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface ThreatEventRepository extends JpaRepository<ThreatEvent, Long>, JpaSpecificationExecutor<ThreatEvent> {
}
