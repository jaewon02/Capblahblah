package com.siem.alarm.detect;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.alarm.event.NormalizedEventDao;
import com.siem.alarm.event.NormalizedEventRow;
import com.siem.alarm.rule.ConditionCodec;
import com.siem.alarm.rule.DetectMethod;
import com.siem.alarm.rule.DetectionRule;
import com.siem.alarm.rule.DetectionRuleRepository;
import com.siem.alarm.rule.RuleDescriber;
import com.siem.alarm.threat.Evidence;
import com.siem.alarm.threat.ThreatService;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 탐지 엔진 (WBS 5.2 · No 130–136).
 *
 * 1회 실행 = 마지막으로 처리한 정규화 이벤트 ID 이후의 이벤트를 batch-size 만큼 읽어
 * 활성 규칙과 비교 → 조건 기반 / 반복 행위 탐지 → 위협 이벤트 · 경보 생성.
 *
 * 처리 위치(cursor)는 메모리에만 둔다 (테이블 명세서에 저장 위치가 없음).
 * 서버 기동 시 startup-lookback-min 만큼 과거부터 다시 읽고, 이미 탐지된 이벤트는 건너뛰어 중복을 막는다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DetectionEngine {

    private final NormalizedEventDao events;
    private final DetectionRuleRepository rules;
    private final ThreatService threatService;
    private final ConditionCodec codec;
    private final ObjectMapper objectMapper;

    @Value("${detection.batch-size:1000}")
    private int batchSize;

    @Value("${detection.startup-lookback-min:60}")
    private int startupLookbackMin;

    /** 마지막으로 처리한 event_id. null = 아직 초기화 전. DetectionRunner 가 직렬 실행을 보장. */
    private Long cursor;

    /** lastEventId: 이번에 읽은 마지막 event_id (없으면 null) */
    public record Result(int processed, int created, Long lastEventId) {
    }

    int batchSize() {
        return batchSize;
    }

    @Transactional
    public Result runOnce() {
        if (cursor == null) {
            cursor = events.cursorSince(Instant.now().minus(Duration.ofMinutes(startupLookbackMin)));
        }
        List<NormalizedEventRow> batch = events.findAfter(cursor, batchSize);
        if (batch.isEmpty()) return new Result(0, 0, null);

        List<EventView> views = batch.stream().map(e -> new EventView(e, objectMapper)).toList();
        int created = 0;
        for (CompiledRule rule : activeRules()) {
            List<EventView> hits = views.stream().filter(rule::matches).toList();
            if (hits.isEmpty()) continue;
            created += rule.rule().getDetectMethod() == DetectMethod.THRESHOLD
                    ? detectThreshold(rule, hits)
                    : detectCondition(rule, hits);
        }
        return new Result(batch.size(), created, batch.get(batch.size() - 1).eventId());
    }

    /** 트랜잭션 커밋 후에 처리 위치를 옮긴다 (실패하면 옮기지 않아 다음 실행에서 같은 batch 를 다시 처리). */
    void advance(long lastEventId) {
        cursor = lastEventId;
    }

    /** 조건 기반 탐지: 일치한 이벤트마다 위협 1건 (중복 억제 시간 안의 같은 그룹 키는 제외). */
    private int detectCondition(CompiledRule rule, List<EventView> hits) {
        DetectionRule r = rule.rule();
        Map<String, Instant> lastInBatch = new HashMap<>();
        int created = 0;
        for (EventView v : hits) {
            NormalizedEventRow e = v.event();
            if (threatService.alreadyLinked(r.getRuleId(), e.eventId())) continue;

            String key = rule.groupKey(v);
            if (suppressed(r, key, e.eventTime(), lastInBatch)) continue;

            Evidence evidence = new Evidence(RuleDescriber.describe(r, rule.conditions()), observed(rule, v));
            threatService.create(r, key, List.of(e), title(r, key, null), evidence);
            lastInBatch.put(key, e.eventTime());
            created++;
        }
        return created;
    }

    /** 반복 행위 탐지: 그룹 키별로 시간 창 안의 일치 이벤트 수를 세어 임계 횟수 이상이면 위협 1건. */
    private int detectThreshold(CompiledRule rule, List<EventView> hits) {
        DetectionRule r = rule.rule();
        Map<String, List<EventView>> byKey = hits.stream()
                .filter(v -> rule.groupKey(v) != null)
                .collect(Collectors.groupingBy(rule::groupKey, LinkedHashMap::new, Collectors.toList()));

        Map<String, Instant> lastInBatch = new HashMap<>();
        int created = 0;
        for (Map.Entry<String, List<EventView>> entry : byKey.entrySet()) {
            String key = entry.getKey();
            Instant latest = entry.getValue().stream()
                    .map(v -> v.event().eventTime())
                    .max(Comparator.naturalOrder())
                    .orElseThrow();
            // 이 시점까지 이미 탐지돼 있으면 건너뜀 (재처리 중복 방지)
            if (threatService.detectedSince(r.getRuleId(), key, latest)) continue;

            Instant from = latest.minusSeconds(r.getTimeWindowSec());
            List<NormalizedEventRow> inWindow = new ArrayList<>();
            for (NormalizedEventRow e : events.findInWindow(from, latest, r.getEventTypeCode(), r.getLogTypeCode())) {
                EventView v = new EventView(e, objectMapper);
                if (rule.matches(v) && key.equals(rule.groupKey(v))) inWindow.add(e);
            }
            int count = inWindow.size();
            if (count < r.getThresholdCount()) continue;
            if (suppressed(r, key, latest, lastInBatch)) continue;

            String observed = count + "회 / " + RuleDescriber.window(r.getTimeWindowSec());
            Evidence evidence = new Evidence(RuleDescriber.describe(r, rule.conditions()), observed);
            threatService.create(r, key, inWindow, title(r, key, observed), evidence);
            lastInBatch.put(key, latest);
            created++;
        }
        return created;
    }

    /** suppress_sec(명세서 기본 0) 안에 같은 규칙 · 같은 그룹 키로 탐지된 건이 있으면 새로 만들지 않음. */
    private boolean suppressed(DetectionRule r, String key, Instant at, Map<String, Instant> lastInBatch) {
        int sec = r.getSuppressSec();
        if (sec <= 0) return false;
        Instant since = at.minusSeconds(sec);
        Instant prev = lastInBatch.get(key);
        if (prev != null && !prev.isBefore(since)) return true;
        return threatService.detectedSince(r.getRuleId(), key, since);
    }

    /** alert.title (탐지 내용) */
    private static String title(DetectionRule r, String key, String observed) {
        String t = r.getName() + (key == null ? "" : " — " + key);
        return observed == null ? t : t + " (" + observed + ")";
    }

    /** 조건 기반 탐지의 관측값: 조건 필드의 실제 값. 예: "extra.COMMAND=/bin/bash" */
    private static String observed(CompiledRule rule, EventView v) {
        if (rule.conditions().isEmpty()) return v.event().eventTypeCode();
        return rule.conditions().stream()
                .map(c -> c.field().equals("event_time")
                        ? "시각=" + v.hourKst() + "시"
                        : c.field() + "=" + Objects.toString(v.value(c.field()), "-"))
                .collect(Collectors.joining(", "));
    }

    private List<CompiledRule> activeRules() {
        List<CompiledRule> list = new ArrayList<>();
        for (DetectionRule r : rules.findByActiveTrueAndDeletedAtIsNull()) {
            try {
                list.add(CompiledRule.of(r, codec));
            } catch (RuntimeException e) {
                // 잘못 저장된 규칙 하나 때문에 전체 탐지가 멈추지 않도록 건너뛴다
                log.error("탐지 규칙 #{} '{}' 조건 오류로 건너뜀: {}", r.getRuleId(), r.getName(), e.getMessage());
            }
        }
        return list;
    }
}
