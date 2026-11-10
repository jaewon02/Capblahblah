package com.siem.alarm.rule;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import java.util.Set;

/**
 * 탐지 조건 1개. detection_rule.condition_expr = {"all":[조건, ...]} (명세서 예시 형식, 모두 만족 시 일치).
 *
 * field: normalized_event 컬럼명 — event_type_code, log_type_code, target_id, source_ip, dest_ip, dest_port,
 *        user_account, host_name, event_time — 또는 extra.<키> (명세서 예: extra.USER)
 * op   : eq, ne, contains, regex, in(value = 배열), between / not_between(숫자 "a-b"),
 *        hour_between / hour_not_between(event_time 의 KST 시각, "9-18" = 09:00~17:59)
 */
public record RuleCondition(
        @NotBlank(message = "조건 필드를 입력하세요.") String field,
        @NotBlank(message = "조건 연산자를 선택하세요.") String op,
        JsonNode value) {

    public static final Set<String> FIELDS = Set.of(
            "event_type_code", "log_type_code", "target_id", "source_ip", "dest_ip", "dest_port",
            "user_account", "host_name", "event_time");

    public static final Set<String> OPS = Set.of(
            "eq", "ne", "contains", "regex", "in", "between", "not_between", "hour_between", "hour_not_between");

    public static boolean isValidField(String field) {
        return FIELDS.contains(field) || (field.startsWith("extra.") && field.length() > "extra.".length());
    }

    /** value 를 문자열로 (배열이면 null). */
    public String text() {
        return value == null || value.isNull() || value.isArray() ? null : value.asText();
    }
}
