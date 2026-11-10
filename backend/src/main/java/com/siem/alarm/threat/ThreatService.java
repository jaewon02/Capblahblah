package com.siem.alarm.threat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.alarm.alert.AlertRepository;
import com.siem.alarm.alert.AlertService;
import com.siem.alarm.common.ApiException;
import com.siem.alarm.common.PageResponse;
import com.siem.alarm.common.Severity;
import com.siem.alarm.event.NormalizedEventDao;
import com.siem.alarm.event.NormalizedEventRow;
import com.siem.alarm.rule.DetectionRule;
import com.siem.alarm.rule.DetectionRuleRepository;
import com.siem.alarm.threat.ThreatDtos.AlertRef;
import com.siem.alarm.threat.ThreatDtos.RelatedLog;
import com.siem.alarm.threat.ThreatDtos.ThreatDetail;
import com.siem.alarm.threat.ThreatDtos.ThreatItem;
import jakarta.persistence.criteria.Predicate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 탐지 결과 생성 (WBS 5.2.3) · 조회 (WBS 5.3).
 * 기능-테이블 매핑 '탐지 실행 · 결과': C threat_event · threat_event_link / U normalized_event(severity)
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ThreatService {

    static final ZoneId KST = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter NO_DATE = DateTimeFormatter.ofPattern("yyyyMMdd");
    /** 위협 1건에 연결하는 근거 이벤트 최대 수 (대량 공격 시 링크 폭증 방지). */
    static final int MAX_LINKS = 500;
    /** 상세 화면에 보여줄 관련 로그 수. */
    static final int DETAIL_LOGS = 20;

    private final JdbcTemplate jdbc;
    private final ThreatEventRepository threats;
    private final DetectionRuleRepository rules;
    private final NormalizedEventDao events;
    private final AlertRepository alerts;
    private final AlertService alertService;
    private final ObjectMapper objectMapper;

    /**
     * 조건 충족 시 위협 이벤트 생성 (No 136):
     * threat_event 저장 → threat_event_link 로 관련 로그 연결 → normalized_event.severity 반영 → 경보 생성 연계.
     */
    @Transactional
    public long create(DetectionRule rule, String groupKey, List<NormalizedEventRow> matched,
                       String alertTitle, Evidence evidence) {
        List<NormalizedEventRow> sorted = matched.stream()
                .sorted(Comparator.comparing(NormalizedEventRow::eventTime))
                .toList();
        NormalizedEventRow first = sorted.get(0);
        NormalizedEventRow last = sorted.get(sorted.size() - 1);
        Severity severity = rule.getSeverity();

        // threat_no = EVT-yyyyMMdd(KST)-시퀀스 (명세서 예: EVT-20261020-0412)
        Long threatId = jdbc.queryForObject(
                "SELECT nextval(pg_get_serial_sequence('threat_event', 'threat_id'))", Long.class);
        String threatNo = "EVT-" + NO_DATE.format(Instant.now().atZone(KST)) + "-" + String.format("%04d", threatId);

        jdbc.update("""
                INSERT INTO threat_event (threat_id, threat_no, rule_id, rule_version, first_event_time, last_event_time,
                                          group_key, source_ip, user_account, target_id, log_type_code, event_count,
                                          severity, original_severity, evidence)
                OVERRIDING SYSTEM VALUE
                VALUES (?, ?, ?, ?, ?, ?, ?, ?::inet, ?, ?, ?, ?, ?, ?, ?::jsonb)
                """,
                threatId, threatNo, rule.getRuleId(), rule.getVersion(),
                NormalizedEventDao.utc(first.eventTime()), NormalizedEventDao.utc(last.eventTime()),
                truncate(groupKey, 200), last.sourceIp(), last.userAccount(), last.targetId(),
                rule.getLogTypeCode() != null ? rule.getLogTypeCode() : last.logTypeCode(),
                sorted.size(), severity.name(), severity.name(), toJson(evidence));

        // 최근 이벤트 위주로 연결
        List<NormalizedEventRow> toLink = sorted.size() > MAX_LINKS
                ? sorted.subList(sorted.size() - MAX_LINKS, sorted.size())
                : sorted;
        jdbc.batchUpdate("INSERT INTO threat_event_link (threat_id, event_id, event_time, raw_log_id) VALUES (?, ?, ?, ?)",
                toLink, toLink.size(), (ps, e) -> {
                    ps.setLong(1, threatId);
                    ps.setLong(2, e.eventId());
                    ps.setObject(3, NormalizedEventDao.utc(e.eventTime()));
                    ps.setLong(4, e.rawLogId());
                });

        // 정규화 이벤트에 검색용 위험 등급 반영 (원천은 threat_event.severity)
        for (NormalizedEventRow e : toLink) {
            Severity current = e.severity() == null ? null : Severity.valueOf(e.severity());
            Severity merged = Severity.max(current, severity);
            if (merged != current) events.updateSeverity(e.eventId(), e.eventTime(), merged.name());
        }

        alertService.createFromThreat(threatId, severity, alertTitle);
        return threatId;
    }

    /** 이 이벤트가 이미 이 규칙의 위협 이벤트 근거로 연결돼 있는지 (재기동 후 재처리 시 중복 방지). */
    public boolean alreadyLinked(long ruleId, long eventId) {
        Boolean b = jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM threat_event_link l JOIN threat_event t ON t.threat_id = l.threat_id
                                WHERE l.event_id = ? AND t.rule_id = ?)
                """, Boolean.class, eventId, ruleId);
        return Boolean.TRUE.equals(b);
    }

    /** 같은 규칙 · 같은 그룹 키로 since 이후의 이벤트까지 이미 탐지했는지 (중복 억제 · 재처리 중복 방지). */
    public boolean detectedSince(long ruleId, String groupKey, Instant since) {
        Boolean b = jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM threat_event
                                WHERE rule_id = ? AND group_key IS NOT DISTINCT FROM ?::varchar AND last_event_time >= ?)
                """, Boolean.class, ruleId, truncate(groupKey, 200), NormalizedEventDao.utc(since));
        return Boolean.TRUE.equals(b);
    }

    public PageResponse<ThreatItem> search(Long ruleId, Severity severity, int page, int size) {
        Specification<ThreatEvent> spec = (root, query, cb) -> {
            List<Predicate> p = new ArrayList<>();
            if (ruleId != null) p.add(cb.equal(root.get("ruleId"), ruleId));
            if (severity != null) p.add(cb.equal(root.get("severity"), severity));
            return cb.and(p.toArray(new Predicate[0]));
        };
        PageRequest pageable = PageRequest.of(page, Math.min(size, 200),
                Sort.by(Sort.Order.desc("detectedAt"), Sort.Order.desc("threatId")));
        Page<ThreatEvent> result = threats.findAll(spec, pageable);
        return PageResponse.of(result, this::toItems);
    }

    public ThreatDetail detail(Long threatId) {
        ThreatEvent t = threats.findById(threatId).orElseThrow(() -> ApiException.notFound("위협 이벤트"));
        ThreatItem item = toItems(List.of(t)).get(0);

        AlertRef alertRef = alerts.findByThreatId(threatId)
                .map(a -> new AlertRef(a.getAlertId(), a.getAlertNo(), a.getStatus(), a.isFalsePositive()))
                .orElse(null);

        List<RelatedLog> logs = events.relatedLogs(threatId, DETAIL_LOGS).stream()
                .map(r -> new RelatedLog(r.eventId(), r.eventTime(), r.eventTypeCode(), r.hostName(), r.sourceIp(),
                        r.userAccount(), r.rawMessage()))
                .toList();

        return new ThreatDetail(item, t.getRuleVersion(), t.getOriginalSeverity(), t.getFirstEventTime(),
                t.getLastEventTime(), fromJson(t.getEvidence()), alertRef, events.countLinks(threatId), logs);
    }

    private List<ThreatItem> toItems(List<ThreatEvent> list) {
        List<Long> ruleIds = list.stream().map(ThreatEvent::getRuleId).distinct().toList();
        Map<Long, DetectionRule> ruleMap = rules.findAllById(ruleIds).stream()
                .collect(Collectors.toMap(DetectionRule::getRuleId, Function.identity()));
        return list.stream().map(t -> {
            DetectionRule r = ruleMap.get(t.getRuleId());
            return new ThreatItem(t.getThreatId(), t.getThreatNo(), t.getDetectedAt(), t.getRuleId(),
                    r == null ? null : r.getName(), t.getGroupKey(), t.getSeverity(), t.getEventCount());
        }).toList();
    }

    private String toJson(Evidence evidence) {
        try {
            return objectMapper.writeValueAsString(evidence);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private Evidence fromJson(String json) {
        if (json == null) return null;
        try {
            return objectMapper.readValue(json, Evidence.class);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    static String truncate(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max);
    }
}
