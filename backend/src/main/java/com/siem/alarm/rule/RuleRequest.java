package com.siem.alarm.rule;

import com.siem.alarm.common.Severity;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.Map;

/** 규칙 등록 · 수정 요청 (No 120–121, 125). 길이 제한은 명세서 컬럼 길이와 같다. */
public record RuleRequest(
        @NotBlank(message = "규칙 이름은 필수입니다.")
        @Size(max = 100, message = "규칙 이름은 100자 이하로 입력하세요.")
        String name,

        @Size(max = 500, message = "설명은 500자 이하로 입력하세요.")
        String description,

        @NotNull(message = "탐지 방식을 선택하세요.")
        DetectMethod detectMethod,

        String logTypeCode,
        String eventTypeCode,
        @Valid List<RuleCondition> conditions,

        /** SOURCE_IP / USER_ACCOUNT / TARGET */
        String groupBy,

        @Positive(message = "시간 창은 1초 이상이어야 합니다.")
        Integer timeWindowSec,

        @Positive(message = "임계 횟수는 1 이상이어야 합니다.")
        Integer thresholdCount,

        @NotNull(message = "위험 등급을 선택하세요.")
        Severity severity,

        @PositiveOrZero(message = "중복 억제 시간은 0 이상이어야 합니다.")
        Integer suppressSec,

        /** 예: {"source_ip":["192.0.2.0/28"],"user_account":["svc-scanner"]} */
        Map<String, List<String>> exceptions,

        @Size(max = 20, message = "ATT&CK 기법은 20자 이하로 입력하세요.")
        String mitreTechnique) {
}
