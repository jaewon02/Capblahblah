package com.siem.alarm.rule;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * detection_rule JSONB 컬럼 변환.
 * condition_expr: {"all":[{"field","op","value"}, ...]}
 * exceptions    : {"source_ip":["192.0.2.0/28"],"user_account":["svc-scanner"]}  (명세서 예시 형식)
 */
@Component
@RequiredArgsConstructor
public class ConditionCodec {

    private static final TypeReference<Map<String, List<RuleCondition>>> CONDITION = new TypeReference<>() {};
    private static final TypeReference<Map<String, List<String>>> EXCEPTIONS = new TypeReference<>() {};

    private final ObjectMapper objectMapper;

    public List<RuleCondition> readConditions(String json) {
        if (json == null || json.isBlank()) return List.of();
        List<RuleCondition> all = parse(json, CONDITION).get("all");
        return all == null ? List.of() : all;
    }

    public String writeConditions(List<RuleCondition> conditions) {
        return write(Map.of("all", conditions == null ? List.of() : conditions));
    }

    public Map<String, List<String>> readExceptions(String json) {
        if (json == null || json.isBlank()) return Map.of();
        return parse(json, EXCEPTIONS);
    }

    /** 비어 있으면 NULL 저장. */
    public String writeExceptions(Map<String, List<String>> exceptions) {
        if (exceptions == null) return null;
        Map<String, List<String>> cleaned = new LinkedHashMap<>();
        exceptions.forEach((k, v) -> {
            if (v != null && !v.isEmpty()) cleaned.put(k, v);
        });
        return cleaned.isEmpty() ? null : write(cleaned);
    }

    private <T> T parse(String json, TypeReference<T> type) {
        try {
            return objectMapper.readValue(json, type);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("JSON 형식 오류: " + json, e);
        }
    }

    private String write(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
