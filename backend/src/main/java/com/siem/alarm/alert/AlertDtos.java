package com.siem.alarm.alert;

import com.siem.alarm.common.Severity;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.time.LocalDate;

public final class AlertDtos {

    private AlertDtos() {
    }

    public record AlertResponse(
            Long alertId,
            String alertNo,
            Instant createdAt,
            Severity severity,
            String title,
            Long threatId,
            String threatNo,
            Long ruleId,
            String ruleName,
            AlertStatus status,
            boolean falsePositive,
            Instant ackedAt,
            Instant resolvedAt) {
    }

    /** 상태 칩 · 메뉴 배지 숫자. */
    public record AlertSummary(
            long total,
            long newCount,
            long ackCount,
            long resolvedCount,
            long falsePositiveCount,
            /** 미확인이면서 오탐이 아닌 건 (메뉴 배지) */
            long unhandledCount) {
    }

    /** 경보 검색 조건 (No 151–152). 날짜는 KST 기준. 비어 있는 항목은 조건에서 제외. */
    public record AlertSearch(
            AlertStatus status,
            Boolean falsePositive,
            Severity severity,
            LocalDate from,
            LocalDate to) {
    }

    public record StatusRequest(@NotNull(message = "변경할 상태를 선택하세요.") AlertStatus status) {
    }

    public record FalsePositiveRequest(
            boolean falsePositive,
            @Size(max = 1000, message = "사유는 1000자 이하로 입력하세요.") String comment) {
    }
}
