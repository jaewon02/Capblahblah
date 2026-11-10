package com.siem.alarm.detect;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.alarm.event.NormalizedEventRow;
import java.time.ZoneId;
import java.util.Map;

/** 정규화 이벤트에서 규칙 조건의 field 값을 꺼내는 래퍼. extra JSONB는 처음 필요할 때 한 번만 파싱. */
final class EventView {

    static final ZoneId KST = ZoneId.of("Asia/Seoul");
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {};

    private final NormalizedEventRow event;
    private final ObjectMapper objectMapper;
    private Map<String, Object> extra;

    EventView(NormalizedEventRow event, ObjectMapper objectMapper) {
        this.event = event;
        this.objectMapper = objectMapper;
    }

    NormalizedEventRow event() {
        return event;
    }

    /** field(normalized_event 컬럼명 또는 extra.<키>)에 해당하는 값. 없으면 null. */
    String value(String field) {
        if (field == null) return null;
        return switch (field) {
            case "event_type_code" -> event.eventTypeCode();
            case "log_type_code" -> event.logTypeCode();
            case "target_id" -> String.valueOf(event.targetId());
            case "source_ip" -> event.sourceIp();
            case "dest_ip" -> event.destIp();
            case "dest_port" -> event.destPort() == null ? null : String.valueOf(event.destPort());
            case "user_account" -> event.userAccount();
            case "host_name" -> event.hostName();
            default -> field.startsWith("extra.") ? extra(field.substring("extra.".length())) : null;
        };
    }

    /** 발생 시각의 KST 시(0–23). 운영 시간 판단용. */
    int hourKst() {
        return event.eventTime().atZone(KST).getHour();
    }

    private String extra(String key) {
        if (extra == null) extra = parseExtra();
        Object v = extra.get(key);
        return v == null ? null : String.valueOf(v);
    }

    private Map<String, Object> parseExtra() {
        String json = event.extra();
        if (json == null || json.isBlank()) return Map.of();
        try {
            return objectMapper.readValue(json, MAP);
        } catch (Exception e) {
            return Map.of();   // 형식 오류는 해당 필드 불일치로 처리
        }
    }
}
