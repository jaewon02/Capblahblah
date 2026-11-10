package com.siem.alarm.alert;

import com.siem.alarm.alert.AlertDtos.AlertResponse;
import com.siem.alarm.alert.AlertDtos.AlertSearch;
import com.siem.alarm.alert.AlertDtos.AlertSummary;
import com.siem.alarm.common.ApiException;
import com.siem.alarm.common.CurrentUser;
import com.siem.alarm.common.PageResponse;
import com.siem.alarm.common.Severity;
import com.siem.alarm.rule.DetectionRule;
import com.siem.alarm.rule.DetectionRuleRepository;
import com.siem.alarm.threat.ThreatEvent;
import com.siem.alarm.threat.ThreatEventRepository;
import jakarta.persistence.criteria.Predicate;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 경보 관리 (WBS 5.4 · No 142–152).
 * 기능-테이블 매핑 '경보 생성 · 처리 · 오탐': C alert · alert_history / R alert · alert_policy / U alert
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AlertService {

    private static final ZoneId KST = ZoneId.of("Asia/Seoul");

    private final JdbcTemplate jdbc;
    private final AlertRepository alerts;
    private final AlertHistoryRepository histories;
    private final ThreatEventRepository threats;
    private final DetectionRuleRepository rules;
    private final CurrentUser currentUser;

    /**
     * 위협 이벤트로부터 경보 자동 생성 (No 143–144). 탐지 엔진 트랜잭션 안에서 호출.
     * alert_policy(등급별 1행)의 alert_mode 에 따라:
     *   IMMEDIATE — 즉시 생성 / NONE — 생성 안 함 /
     *   THRESHOLD — 같은 등급 위협 이벤트가 threshold_window_sec 안에 threshold_count 건 이상이면 생성
     * @return 생성된 alert_id, 생성하지 않았으면 null
     */
    @Transactional
    public Long createFromThreat(long threatId, Severity severity, String title) {
        List<Map<String, Object>> policy = jdbc.queryForList(
                "SELECT alert_mode, threshold_count, threshold_window_sec FROM alert_policy WHERE severity = ?",
                severity.name());
        if (policy.isEmpty()) return null;
        String mode = (String) policy.get(0).get("alert_mode");
        if ("NONE".equals(mode)) return null;
        if ("THRESHOLD".equals(mode)) {
            Integer count = (Integer) policy.get(0).get("threshold_count");
            Integer windowSec = (Integer) policy.get(0).get("threshold_window_sec");
            if (count == null || windowSec == null) return null;
            Integer recent = jdbc.queryForObject("""
                    SELECT count(*) FROM threat_event
                     WHERE severity = ? AND detected_at >= now() - make_interval(secs => ?)
                    """, Integer.class, severity.name(), windowSec);
            if (recent == null || recent < count) return null;
        }

        // alert_no = ALT-시퀀스 (명세서: 예 ALT-0091, 시퀀스 기반, 접미사 금지)
        Long alertId = jdbc.queryForObject("SELECT nextval(pg_get_serial_sequence('alert', 'alert_id'))", Long.class);
        String alertNo = String.format("ALT-%04d", alertId);
        jdbc.update("""
                INSERT INTO alert (alert_id, alert_no, threat_id, severity, title)
                OVERRIDING SYSTEM VALUE
                VALUES (?, ?, ?, ?, ?)
                """, alertId, alertNo, threatId, severity.name(), title.length() > 300 ? title.substring(0, 300) : title);
        // 시스템 자동 생성 → actor_id NULL
        jdbc.update("INSERT INTO alert_history (alert_id, action, from_value, to_value) VALUES (?, ?, NULL, ?)",
                alertId, AlertHistory.ACTION_STATUS, AlertStatus.NEW.name());
        return alertId;
    }

    /** 경보 목록 · 검색. 최신순 정렬 (No 146, 152). */
    public PageResponse<AlertResponse> search(AlertSearch cond, int page, int size) {
        PageRequest pageable = PageRequest.of(page, Math.min(size, 200),
                Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("alertId")));
        Page<Alert> result = alerts.findAll(spec(cond), pageable);
        return PageResponse.of(result, this::toResponses);
    }

    /** 상태별 건수. 위험 등급 · 기간 조건은 적용하고 상태 · 오탐 조건은 무시. */
    public AlertSummary summary(AlertSearch cond) {
        AlertSearch base = new AlertSearch(null, null, cond.severity(), cond.from(), cond.to());
        long total = alerts.count(spec(base));
        long newCount = alerts.count(spec(with(base, AlertStatus.NEW, null)));
        long ackCount = alerts.count(spec(with(base, AlertStatus.ACK, null)));
        long resolvedCount = alerts.count(spec(with(base, AlertStatus.RESOLVED, null)));
        long fpCount = alerts.count(spec(with(base, null, true)));
        long unhandled = alerts.count(spec(with(base, AlertStatus.NEW, false)));
        return new AlertSummary(total, newCount, ackCount, resolvedCount, fpCount, unhandled);
    }

    public AlertResponse get(Long alertId) {
        return toResponses(List.of(find(alertId))).get(0);
    }

    public List<AlertHistory> histories(Long alertId) {
        find(alertId);
        return histories.findByAlertIdOrderByCreatedAtAscHistoryIdAsc(alertId);
    }

    /** 상태는 한 단계씩만 진행: 미확인 → 확인 → 처리 완료 (No 148). */
    @Transactional
    public AlertResponse changeStatus(Long alertId, AlertStatus target) {
        Alert alert = find(alertId);
        AlertStatus current = alert.getStatus();
        if (current.next() != target) {
            throw new ApiException(HttpStatus.CONFLICT,
                    "상태는 미확인 → 확인 → 처리 완료 순서로만 바꿀 수 있습니다. (현재: " + current + ")");
        }

        Instant now = Instant.now();
        alert.setStatus(target);
        if (target == AlertStatus.ACK) alert.setAckedAt(now);
        if (target == AlertStatus.RESOLVED) alert.setResolvedAt(now);
        alert.setUpdatedAt(now);
        history(alertId, AlertHistory.ACTION_STATUS, current.name(), target.name(), null);
        return get(alertId);
    }

    /** 오탐 지정 · 해제. 상태와 별개로 관리하고 내역을 남긴다 (No 150). */
    @Transactional
    public AlertResponse setFalsePositive(Long alertId, boolean falsePositive, String comment) {
        Alert alert = find(alertId);
        if (alert.isFalsePositive() == falsePositive) return get(alertId);

        alert.setFalsePositive(falsePositive);
        alert.setUpdatedAt(Instant.now());
        history(alertId, AlertHistory.ACTION_FALSE_POSITIVE,
                String.valueOf(!falsePositive), String.valueOf(falsePositive), comment);
        return get(alertId);
    }

    private Alert find(Long alertId) {
        return alerts.findById(alertId).orElseThrow(() -> ApiException.notFound("경보"));
    }

    private void history(Long alertId, String action, String from, String to, String comment) {
        AlertHistory h = new AlertHistory();
        h.setAlertId(alertId);
        h.setAction(action);
        h.setFromValue(from);
        h.setToValue(to);
        h.setComment(comment == null || comment.isBlank() ? null : comment.trim());
        h.setActorId(currentUser.userId());
        h.setCreatedAt(Instant.now());
        histories.save(h);
    }

    private List<AlertResponse> toResponses(List<Alert> list) {
        List<Long> threatIds = list.stream().map(Alert::getThreatId).toList();
        Map<Long, ThreatEvent> threatMap = threats.findAllById(threatIds).stream()
                .collect(Collectors.toMap(ThreatEvent::getThreatId, Function.identity()));
        List<Long> ruleIds = threatMap.values().stream().map(ThreatEvent::getRuleId).distinct().toList();
        Map<Long, DetectionRule> ruleMap = rules.findAllById(ruleIds).stream()
                .collect(Collectors.toMap(DetectionRule::getRuleId, Function.identity()));

        return list.stream().map(a -> {
            ThreatEvent t = threatMap.get(a.getThreatId());
            DetectionRule r = t == null ? null : ruleMap.get(t.getRuleId());
            return new AlertResponse(a.getAlertId(), a.getAlertNo(), a.getCreatedAt(), a.getSeverity(), a.getTitle(),
                    a.getThreatId(), t == null ? null : t.getThreatNo(),
                    r == null ? null : r.getRuleId(), r == null ? null : r.getName(),
                    a.getStatus(), a.isFalsePositive(), a.getAckedAt(), a.getResolvedAt());
        }).toList();
    }

    private static AlertSearch with(AlertSearch base, AlertStatus status, Boolean falsePositive) {
        return new AlertSearch(status, falsePositive, base.severity(), base.from(), base.to());
    }

    private static Specification<Alert> spec(AlertSearch c) {
        return (root, query, cb) -> {
            List<Predicate> p = new ArrayList<>();
            if (c.status() != null) p.add(cb.equal(root.get("status"), c.status()));
            if (c.falsePositive() != null) p.add(cb.equal(root.get("falsePositive"), c.falsePositive()));
            if (c.severity() != null) p.add(cb.equal(root.get("severity"), c.severity()));
            if (c.from() != null) {
                p.add(cb.greaterThanOrEqualTo(root.<Instant>get("createdAt"), c.from().atStartOfDay(KST).toInstant()));
            }
            if (c.to() != null) {
                p.add(cb.lessThan(root.<Instant>get("createdAt"), c.to().plusDays(1).atStartOfDay(KST).toInstant()));
            }
            return cb.and(p.toArray(new Predicate[0]));
        };
    }
}
