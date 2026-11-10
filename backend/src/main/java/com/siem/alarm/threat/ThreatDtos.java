package com.siem.alarm.threat;

import com.siem.alarm.alert.AlertStatus;
import com.siem.alarm.common.Severity;
import java.time.Instant;
import java.util.List;

public final class ThreatDtos {

    private ThreatDtos() {
    }

    /** 탐지된 위협 목록 한 줄 (No 139: 탐지 시각, 규칙, 위험 등급). */
    public record ThreatItem(
            Long threatId,
            String threatNo,
            Instant detectedAt,
            Long ruleId,
            String ruleName,
            String groupKey,
            Severity severity,
            int eventCount) {
    }

    /** 탐지 근거 및 관련 로그 (No 141). */
    public record ThreatDetail(
            ThreatItem threat,
            int ruleVersion,
            Severity originalSeverity,
            Instant firstEventTime,
            Instant lastEventTime,
            Evidence evidence,
            AlertRef alert,
            int linkedLogCount,
            List<RelatedLog> logs) {
    }

    public record AlertRef(Long alertId, String alertNo, AlertStatus status, boolean falsePositive) {
    }

    public record RelatedLog(
            Long eventId,
            Instant eventTime,
            String eventTypeCode,
            String hostName,
            String sourceIp,
            String userAccount,
            /** raw_log.raw_message 원문 */
            String raw) {
    }
}
