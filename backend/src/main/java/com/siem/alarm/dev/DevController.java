package com.siem.alarm.dev;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.alarm.common.ApiException;
import com.siem.alarm.detect.DetectionEngine;
import com.siem.alarm.detect.DetectionRunner;
import com.siem.alarm.event.NormalizedEventDao;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 개발 전용 (dev 프로필에서만 등록).
 * 파싱 · 정규화 엔진(WBS 3.5)이 완성되기 전에 탐지 · 경보를 시험하기 위해
 * collect_target · raw_log · normalized_event 에 테스트 데이터를 명세서 컬럼 그대로 넣는다.
 */
@Profile("dev")
@RestController
@RequestMapping("/api/dev")
@RequiredArgsConstructor
public class DevController {

    private static final ZoneId KST = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter SYSLOG_TIME =
            DateTimeFormatter.ofPattern("MMM dd HH:mm:ss", Locale.ENGLISH).withZone(KST);

    /** 테스트용 수집 대상: 이름, IP, 로그 유형 */
    private static final Map<String, String[]> TARGETS = Map.of(
            "bastion", new String[] {"10.0.0.5", "AUTH"},
            "db-01", new String[] {"10.0.0.21", "SYSTEM"},
            "web-01", new String[] {"10.0.0.31", "WEB"});

    private final JdbcTemplate jdbc;
    private final DetectionRunner runner;
    private final ObjectMapper objectMapper;

    /**
     * 시나리오: ssh-bruteforce | sudo-root | offhours-login | user-created | web-admin-scan
     * 예) POST /api/dev/simulate/ssh-bruteforce
     */
    @PostMapping("/simulate/{scenario}")
    @Transactional
    public Map<String, Object> simulate(@PathVariable String scenario) {
        Instant now = Instant.now();
        int count = switch (scenario) {
            case "ssh-bruteforce" -> {
                for (int i = 0; i < 15; i++) {
                    Instant t = now.minusSeconds(15 - i);
                    String user = i % 3 == 0 ? "admin" : "root";
                    save(t, "bastion", "AUTH", "ssh_auth_failed", "203.0.113.47", user, null,
                            "bastion sshd[" + (2200 + i) + "]: Failed password for " + user
                                    + " from 203.0.113.47 port " + (52200 + i) + " ssh2");
                }
                yield 15;
            }
            case "sudo-root" -> {
                save(now, "db-01", "AUTH", "sudo_exec", "10.0.0.21", "deploy",
                        Map.of("USER", "root", "COMMAND", "/bin/bash"),
                        "db-01 sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash");
                yield 1;
            }
            case "offhours-login" -> {
                Instant t = now.atZone(KST).withHour(2).withMinute(13).toInstant();
                save(t, "bastion", "AUTH", "ssh_login_success", "198.51.100.12", "kim", null,
                        "bastion sshd[811]: Accepted publickey for kim from 198.51.100.12 port 40022 ssh2");
                yield 1;
            }
            case "user-created" -> {
                save(now, "db-01", "SYSTEM", "user_created", null, "deploy", Map.of("new_user", "backup2"),
                        "db-01 useradd[3012]: new user: name=backup2, UID=1005, GID=1005");
                yield 1;
            }
            case "web-admin-scan" -> {
                for (int i = 0; i < 25; i++) {
                    save(now.minusSeconds(25 - i), "web-01", "WEB", "http_403", "198.51.100.230", null,
                            Map.of("path", "/admin/login.php", "status", 403),
                            "198.51.100.230 - - \"GET /admin/login.php HTTP/1.1\" 403 162");
                }
                yield 25;
            }
            default -> throw ApiException.badRequest("알 수 없는 시나리오: " + scenario);
        };
        return Map.of("scenario", scenario, "inserted", count);
    }

    /** 다음 스케줄(10초)을 기다리지 않고 탐지 엔진 즉시 실행. */
    @PostMapping("/detect")
    public DetectionEngine.Result detectNow() {
        return runner.runAll();
    }

    private void save(Instant t, String host, String logType, String eventType, String srcIp, String user,
                      Map<String, Object> extra, String body) {
        long targetId = target(host);
        String rawMessage = SYSLOG_TIME.format(t) + " " + body;

        // raw_log: 파티션 키(received_at) 포함 PK. 같은 트랜잭션에서 normalized_event 와 함께 INSERT
        Map<String, Object> raw = jdbc.queryForMap("""
                INSERT INTO raw_log (received_at, target_id, log_type_code, sender_ip, raw_message, dedup_hash, parse_status)
                VALUES (?, ?, ?, ?::inet, ?, ?, 'SUCCESS')
                RETURNING raw_log_id, received_at
                """, NormalizedEventDao.utc(t), targetId, logType, TARGETS.get(host)[0], rawMessage, sha256(rawMessage));

        Map<String, Object> normalized = new LinkedHashMap<>();
        normalized.put("event_time", t.toString());
        normalized.put("log_type", logType);
        normalized.put("event_type", eventType);
        normalized.put("source_ip", srcIp);
        normalized.put("user_account", user);
        normalized.put("host_name", host);
        normalized.put("extra", extra);

        jdbc.update("""
                INSERT INTO normalized_event (event_time, raw_log_id, raw_received_at, target_id, log_type_code,
                                              event_type_code, source_ip, user_account, host_name, extra, normalized_json)
                VALUES (?, ?, ?, ?, ?, ?, ?::inet, ?, ?, ?::jsonb, ?::jsonb)
                """, NormalizedEventDao.utc(t), raw.get("raw_log_id"), raw.get("received_at"), targetId, logType,
                eventType, srcIp, user, host, extra == null ? null : json(extra), json(normalized));
    }

    /** 테스트용 수집 대상 조회, 없으면 생성. */
    private long target(String name) {
        Long id = jdbc.query("SELECT target_id FROM collect_target WHERE name = ? AND deleted_at IS NULL",
                rs -> rs.next() ? rs.getLong(1) : null, name);
        if (id != null) return id;
        String[] t = TARGETS.get(name);
        return jdbc.queryForObject("""
                INSERT INTO collect_target (name, ip_address, description, log_type_code, collect_method, syslog_protocol, syslog_port)
                VALUES (?, ?::inet, '개발용 테스트 대상', ?, 'SYSLOG', 'UDP', 514)
                RETURNING target_id
                """, Long.class, name, t[0], t[1]);
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
