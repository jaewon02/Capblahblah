package com.siem.alarm.detect;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 탐지 엔진을 주기적으로 실행. 쌓인 이벤트가 많으면 batch가 빌 때까지 반복.
 * 실행할 때마다 service_status 의 DETECTOR heartbeat 갱신 (명세서 TB_26, No 229–233).
 * synchronized: 스케줄 실행과 수동 실행(/api/dev/detect)이 겹쳐 중복 탐지되지 않도록.
 * (서버 1대 기준. 여러 대로 늘리면 DB 락 등 분산 잠금 필요)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DetectionRunner {

    private static final String SERVICE_CODE = "DETECTOR";
    private static final String VERSION = "0.1.0";

    private final DetectionEngine engine;
    private final JdbcTemplate jdbc;

    @Scheduled(fixedDelayString = "${detection.interval-ms:10000}", initialDelay = 5000)
    public void scheduled() {
        try {
            runAll();
        } catch (RuntimeException e) {
            log.error("탐지 엔진 실행 실패", e);
            heartbeat("DEGRADED", "탐지 실패: " + e.getMessage());
        }
    }

    public synchronized DetectionEngine.Result runAll() {
        int processed = 0;
        int created = 0;
        DetectionEngine.Result r;
        do {
            r = engine.runOnce();            // 트랜잭션 커밋까지 끝난 뒤 반환
            if (r.lastEventId() != null) engine.advance(r.lastEventId());
            processed += r.processed();
            created += r.created();
        } while (r.processed() >= engine.batchSize());

        if (created > 0) log.info("탐지 완료: 이벤트 {}건 처리, 위협 이벤트 {}건 생성", processed, created);
        heartbeat("UP", "최근 실행: 이벤트 " + processed + "건 처리, 위협 이벤트 " + created + "건 생성");
        return new DetectionEngine.Result(processed, created, r.lastEventId());
    }

    private void heartbeat(String status, String message) {
        try {
            jdbc.update("""
                    INSERT INTO service_status (service_code, name, status, version, message, last_heartbeat_at)
                    VALUES (?, '탐지 엔진', ?, ?, ?, now())
                    ON CONFLICT (service_code) DO UPDATE
                       SET status = EXCLUDED.status, version = EXCLUDED.version,
                           message = EXCLUDED.message, last_heartbeat_at = EXCLUDED.last_heartbeat_at
                    """, SERVICE_CODE, status, VERSION, message.length() > 300 ? message.substring(0, 300) : message);
        } catch (RuntimeException e) {
            log.warn("service_status 갱신 실패: {}", e.getMessage());
        }
    }
}
