package com.siem.alarm.rule;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/** 규칙 조건을 사람이 읽는 한 줄로 만든다. 예: "ssh_auth_failed ≥ 10회 / 5분 · 출발지 IP" */
public final class RuleDescriber {

    /** detection_rule.group_by 값 (명세서: SOURCE_IP/USER_ACCOUNT/TARGET) */
    public static final Map<String, String> GROUP_LABELS = Map.of(
            "SOURCE_IP", "출발지 IP",
            "USER_ACCOUNT", "사용자 계정",
            "TARGET", "수집 대상");

    private RuleDescriber() {
    }

    public static String describe(DetectionRule rule, List<RuleCondition> conditions) {
        List<String> parts = new ArrayList<>();
        if (rule.getEventTypeCode() != null) parts.add(rule.getEventTypeCode());
        for (RuleCondition c : conditions) parts.add(describe(c));
        String base = parts.isEmpty() ? "(모든 이벤트)" : String.join(" AND ", parts);

        if (rule.getDetectMethod() == DetectMethod.THRESHOLD) {
            String group = GROUP_LABELS.getOrDefault(rule.getGroupBy(), rule.getGroupBy());
            return base + " ≥ " + rule.getThresholdCount() + "회 / " + window(rule.getTimeWindowSec()) + " · " + group;
        }
        return base;
    }

    public static String describe(RuleCondition c) {
        String v = valueText(c.value());
        return switch (c.op()) {
            case "eq" -> c.field() + "=" + v;
            case "ne" -> c.field() + "≠" + v;
            case "in" -> c.field() + " ∈ {" + v + "}";
            case "contains" -> c.field() + " contains \"" + v + "\"";
            case "regex" -> c.field() + " ~ /" + v + "/";
            case "between" -> c.field() + " ∈ [" + v.replace("-", "–") + "]";
            case "not_between" -> c.field() + " ∉ [" + v.replace("-", "–") + "]";
            case "hour_between" -> "시각 ∈ [" + v.replace("-", "–") + "시]";
            case "hour_not_between" -> "시각 ∉ [" + v.replace("-", "–") + "시]";
            default -> c.field() + " " + c.op() + " " + v;
        };
    }

    public static String window(Integer sec) {
        if (sec == null) return "-";
        if (sec % 3600 == 0) return (sec / 3600) + "시간";
        if (sec % 60 == 0) return (sec / 60) + "분";
        return sec + "초";
    }

    private static String valueText(JsonNode value) {
        if (value == null || value.isNull()) return "";
        if (value.isArray()) {
            return StreamSupport.stream(value.spliterator(), false).map(JsonNode::asText)
                    .collect(Collectors.joining(", "));
        }
        return value.asText();
    }
}
