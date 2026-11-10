package com.siem.alarm.rule;

import com.fasterxml.jackson.databind.JsonNode;
import com.siem.alarm.code.EventTypeRepository;
import com.siem.alarm.code.LogTypeRepository;
import com.siem.alarm.common.ApiException;
import com.siem.alarm.common.AuditService;
import com.siem.alarm.common.CurrentUser;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 탐지 규칙 관리 (WBS 5.1 · No 118–129).
 * 기능-테이블 매핑: C detection_rule · admin_audit_log / R · U detection_rule / D detection_rule(논리)
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DetectionRuleService {

    private static final String MENU = "위협 탐지 규칙";
    private static final String TABLE = "detection_rule";
    private static final Pattern RANGE = Pattern.compile("\\s*-?\\d+\\s*-\\s*-?\\d+\\s*");
    private static final Set<String> HOUR_OPS = Set.of("hour_between", "hour_not_between");

    private final DetectionRuleRepository repository;
    private final LogTypeRepository logTypes;
    private final EventTypeRepository eventTypes;
    private final ConditionCodec codec;
    private final AuditService audit;
    private final CurrentUser currentUser;

    public List<RuleResponse> list() {
        return repository.findByDeletedAtIsNullOrderByRuleIdAsc().stream().map(this::toResponse).toList();
    }

    public RuleResponse get(Long ruleId) {
        return toResponse(find(ruleId));
    }

    @Transactional
    public RuleResponse create(RuleRequest req) {
        validate(req);
        Instant now = Instant.now();
        DetectionRule rule = new DetectionRule();
        apply(rule, req);
        rule.setActive(true);
        rule.setVersion(1);
        rule.setCreatedBy(currentUser.userId());
        rule.setCreatedAt(now);
        rule.setUpdatedAt(now);
        repository.save(rule);

        RuleResponse after = toResponse(rule);
        audit.record(MENU, AuditService.CREATE, TABLE, rule.getRuleId(), null, after,
                "탐지 규칙 등록: " + rule.getName());
        return after;
    }

    /** 조건 변경 → version +1, 변경 내역을 관리자 이력에 기록 (No 125). */
    @Transactional
    public RuleResponse update(Long ruleId, RuleRequest req) {
        validate(req);
        DetectionRule rule = find(ruleId);
        RuleResponse before = toResponse(rule);

        apply(rule, req);
        rule.setVersion(rule.getVersion() + 1);
        rule.setUpdatedBy(currentUser.userId());
        rule.setUpdatedAt(Instant.now());

        RuleResponse after = toResponse(rule);
        audit.record(MENU, AuditService.UPDATE, TABLE, ruleId, before, after,
                "탐지 규칙 수정: " + rule.getName() + " (v" + before.version() + " → v" + after.version() + ")");
        return after;
    }

    /** 활성화 / 비활성화 (No 129). */
    @Transactional
    public RuleResponse setActive(Long ruleId, boolean active) {
        DetectionRule rule = find(ruleId);
        if (rule.isActive() == active) return toResponse(rule);

        rule.setActive(active);
        rule.setUpdatedBy(currentUser.userId());
        rule.setUpdatedAt(Instant.now());
        audit.record(MENU, AuditService.UPDATE, TABLE, ruleId,
                Map.of("is_active", !active), Map.of("is_active", active),
                "탐지 규칙 " + (active ? "활성화" : "비활성화") + ": " + rule.getName());
        return toResponse(rule);
    }

    /** 논리 삭제 (No 127). 과거 탐지 근거 보존을 위해 행은 남긴다. */
    @Transactional
    public void delete(Long ruleId) {
        DetectionRule rule = find(ruleId);
        RuleResponse before = toResponse(rule);
        Instant now = Instant.now();
        rule.setDeletedAt(now);
        rule.setUpdatedBy(currentUser.userId());
        rule.setUpdatedAt(now);
        audit.record(MENU, AuditService.DELETE, TABLE, ruleId, before, null, "탐지 규칙 삭제: " + rule.getName());
    }

    public RuleResponse toResponse(DetectionRule r) {
        List<RuleCondition> conditions = codec.readConditions(r.getConditionExpr());
        return new RuleResponse(
                r.getRuleId(), r.getName(), r.getDescription(), r.getDetectMethod(),
                r.getLogTypeCode(), r.getEventTypeCode(), conditions, r.getGroupBy(),
                r.getTimeWindowSec(), r.getThresholdCount(), r.getSeverity(), r.getSuppressSec(),
                codec.readExceptions(r.getExceptions()), r.getMitreTechnique(), r.isActive(), r.getVersion(),
                RuleDescriber.describe(r, conditions),
                r.getCreatedBy(), r.getCreatedAt(), r.getUpdatedBy(), r.getUpdatedAt());
    }

    private DetectionRule find(Long ruleId) {
        return repository.findByRuleIdAndDeletedAtIsNull(ruleId).orElseThrow(() -> ApiException.notFound("탐지 규칙"));
    }

    private void apply(DetectionRule rule, RuleRequest req) {
        boolean threshold = req.detectMethod() == DetectMethod.THRESHOLD;
        rule.setName(req.name().trim());
        rule.setDescription(blankToNull(req.description()));
        rule.setDetectMethod(req.detectMethod());
        rule.setLogTypeCode(blankToNull(req.logTypeCode()));
        rule.setEventTypeCode(blankToNull(req.eventTypeCode()));
        rule.setConditionExpr(codec.writeConditions(req.conditions()));
        rule.setGroupBy(blankToNull(req.groupBy()));
        rule.setTimeWindowSec(threshold ? req.timeWindowSec() : null);
        rule.setThresholdCount(threshold ? req.thresholdCount() : null);
        rule.setSeverity(req.severity());
        rule.setSuppressSec(req.suppressSec() == null ? 0 : req.suppressSec());
        rule.setExceptions(codec.writeExceptions(req.exceptions()));
        rule.setMitreTechnique(blankToNull(req.mitreTechnique()));
    }

    private void validate(RuleRequest req) {
        String logType = blankToNull(req.logTypeCode());
        String eventType = blankToNull(req.eventTypeCode());
        if (logType != null && !logTypes.existsById(logType)) {
            throw ApiException.badRequest("알 수 없는 로그 유형입니다: " + logType);
        }
        if (eventType != null && !eventTypes.existsById(eventType)) {
            throw ApiException.badRequest("알 수 없는 이벤트 유형입니다: " + eventType);
        }
        String groupBy = blankToNull(req.groupBy());
        if (groupBy != null && !RuleDescriber.GROUP_LABELS.containsKey(groupBy)) {
            throw ApiException.badRequest("그룹 기준은 SOURCE_IP, USER_ACCOUNT, TARGET 중 하나여야 합니다.");
        }

        List<RuleCondition> conditions = req.conditions() == null ? List.of() : req.conditions();
        if (req.detectMethod() == DetectMethod.THRESHOLD) {
            // 명세서 CHECK: THRESHOLD 이면 time_window_sec > 0 AND threshold_count > 0 AND group_by IS NOT NULL
            if (groupBy == null) throw ApiException.badRequest("반복 행위 탐지는 그룹 기준이 필요합니다.");
            if (req.timeWindowSec() == null) throw ApiException.badRequest("시간 창을 입력하세요.");
            if (req.thresholdCount() == null) throw ApiException.badRequest("임계 횟수를 입력하세요.");
        } else if (eventType == null && conditions.isEmpty()) {
            throw ApiException.badRequest("조건 기반 탐지는 이벤트 유형 또는 조건이 하나 이상 필요합니다.");
        }

        for (RuleCondition c : conditions) validateCondition(c);
        if (req.exceptions() != null) {
            for (String key : req.exceptions().keySet()) {
                if (!RuleCondition.isValidField(key) || key.equals("event_time")) {
                    throw ApiException.badRequest("예외 조건에 쓸 수 없는 필드입니다: " + key);
                }
            }
        }
    }

    private void validateCondition(RuleCondition c) {
        if (!RuleCondition.isValidField(c.field())) {
            throw ApiException.badRequest("지원하지 않는 조건 필드입니다: " + c.field());
        }
        if (!RuleCondition.OPS.contains(c.op())) {
            throw ApiException.badRequest("지원하지 않는 연산자입니다: " + c.op());
        }
        boolean hourOp = HOUR_OPS.contains(c.op());
        if (hourOp != c.field().equals("event_time")) {
            throw ApiException.badRequest("발생 시각(event_time)은 시각 범위 연산자로만 비교할 수 있습니다.");
        }
        JsonNode v = c.value();
        if (c.op().equals("in")) {
            if (v == null || !v.isArray() || v.isEmpty()) throw ApiException.badRequest("'목록 중 하나'는 값이 하나 이상 필요합니다.");
            return;
        }
        String text = c.text();
        if (text == null) throw ApiException.badRequest("조건 값을 입력하세요: " + c.field());
        if (c.op().equals("regex")) {
            try {
                Pattern.compile(text);
            } catch (PatternSyntaxException e) {
                throw ApiException.badRequest("정규식 형식 오류: " + text);
            }
        }
        if ((hourOp || c.op().endsWith("between")) && !RANGE.matcher(text).matches()) {
            throw ApiException.badRequest("범위는 \"9-18\" 형식으로 입력하세요.");
        }
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
