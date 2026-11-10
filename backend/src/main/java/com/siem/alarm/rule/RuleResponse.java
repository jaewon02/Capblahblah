package com.siem.alarm.rule;

import com.siem.alarm.common.Severity;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public record RuleResponse(
        Long ruleId,
        String name,
        String description,
        DetectMethod detectMethod,
        String logTypeCode,
        String eventTypeCode,
        List<RuleCondition> conditions,
        String groupBy,
        Integer timeWindowSec,
        Integer thresholdCount,
        Severity severity,
        int suppressSec,
        Map<String, List<String>> exceptions,
        String mitreTechnique,
        boolean active,
        int version,
        /** 목록 · 탐지 근거 화면에 보여줄 조건 요약 문자열 */
        String conditionText,
        Long createdBy,
        Instant createdAt,
        Long updatedBy,
        Instant updatedAt) {
}
