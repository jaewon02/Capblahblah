package com.siem.alarm.event;

import java.time.Instant;

/** TB_13 normalized_event 한 행 (탐지 엔진 입력). PK = (eventId, eventTime) */
public record NormalizedEventRow(
        long eventId,
        Instant eventTime,
        long rawLogId,
        Instant rawReceivedAt,
        long targetId,
        String logTypeCode,
        String eventTypeCode,
        String sourceIp,
        String destIp,
        Integer destPort,
        String userAccount,
        String hostName,
        String severity,
        /** extra JSONB 원문 */
        String extra) {
}
