package com.siem.alarm.event;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * normalized_event · raw_log 조회 (파티션 테이블이라 복합 PK · 파티션 키 조건이 필요해 JDBC로 직접 다룬다).
 * 기능-테이블 매핑 '탐지 실행 · 결과': R normalized_event, U normalized_event(severity).
 */
@Repository
@RequiredArgsConstructor
public class NormalizedEventDao {

    private static final String COLUMNS = """
            event_id, event_time, raw_log_id, raw_received_at, target_id, log_type_code, event_type_code,
            host(source_ip) AS source_ip, host(dest_ip) AS dest_ip, dest_port, user_account, host_name,
            severity, extra::text AS extra
            """;

    private final JdbcTemplate jdbc;

    /** 탐지 엔진: 마지막 처리 ID 이후의 신규 이벤트 (event_id 는 단일 시퀀스라 파티션과 무관하게 증가). */
    public List<NormalizedEventRow> findAfter(long lastEventId, int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM normalized_event WHERE event_id > ? ORDER BY event_id LIMIT ?",
                this::map, lastEventId, limit);
    }

    /** 기동 시 처리 시작 위치: 이 시각 이후 이벤트 중 가장 작은 ID - 1. 없으면 현재 최대 ID. */
    public long cursorSince(Instant since) {
        Long min = jdbc.queryForObject("SELECT min(event_id) FROM normalized_event WHERE event_time >= ?",
                Long.class, utc(since));
        if (min != null) return min - 1;
        Long max = jdbc.queryForObject("SELECT max(event_id) FROM normalized_event", Long.class);
        return max == null ? 0 : max;
    }

    /** 반복 행위 탐지: 시간 창 안의 이벤트. 이벤트 유형 · 로그 유형이 지정된 경우만 조건에 넣는다. */
    public List<NormalizedEventRow> findInWindow(Instant from, Instant to, String eventTypeCode, String logTypeCode) {
        StringBuilder sql = new StringBuilder("SELECT " + COLUMNS + " FROM normalized_event WHERE event_time BETWEEN ? AND ?");
        List<Object> args = new ArrayList<>(List.of(utc(from), utc(to)));
        if (eventTypeCode != null) {
            sql.append(" AND event_type_code = ?");
            args.add(eventTypeCode);
        }
        if (logTypeCode != null) {
            sql.append(" AND log_type_code = ?");
            args.add(logTypeCode);
        }
        sql.append(" ORDER BY event_time");
        return jdbc.query(sql.toString(), this::map, args.toArray());
    }

    /** 탐지된 이벤트에 위협 이벤트 등급 반영 (명세서: 검색용 반영 값). */
    public void updateSeverity(long eventId, Instant eventTime, String severity) {
        jdbc.update("UPDATE normalized_event SET severity = ? WHERE event_id = ? AND event_time = ?",
                severity, eventId, utc(eventTime));
    }

    /** 위협 이벤트의 관련 로그 원문 (최근순). threat_event_link → normalized_event → raw_log */
    public List<RelatedLogRow> relatedLogs(long threatId, int limit) {
        return jdbc.query("""
                SELECT l.event_id, l.event_time, ne.event_type_code, ne.host_name,
                       host(ne.source_ip) AS source_ip, ne.user_account, r.raw_message
                  FROM threat_event_link l
                  JOIN normalized_event ne ON ne.event_id = l.event_id AND ne.event_time = l.event_time
                  LEFT JOIN raw_log r ON r.raw_log_id = ne.raw_log_id AND r.received_at = ne.raw_received_at
                 WHERE l.threat_id = ?
                 ORDER BY l.event_time DESC
                 LIMIT ?
                """, (rs, i) -> new RelatedLogRow(
                rs.getLong("event_id"), instant(rs, "event_time"), rs.getString("event_type_code"),
                rs.getString("host_name"), rs.getString("source_ip"), rs.getString("user_account"),
                rs.getString("raw_message")), threatId, limit);
    }

    public int countLinks(long threatId) {
        Integer n = jdbc.queryForObject("SELECT count(*) FROM threat_event_link WHERE threat_id = ?", Integer.class, threatId);
        return n == null ? 0 : n;
    }

    public record RelatedLogRow(long eventId, Instant eventTime, String eventTypeCode, String hostName,
                                String sourceIp, String userAccount, String rawMessage) {
    }

    private NormalizedEventRow map(ResultSet rs, int rowNum) throws SQLException {
        return new NormalizedEventRow(
                rs.getLong("event_id"),
                instant(rs, "event_time"),
                rs.getLong("raw_log_id"),
                instant(rs, "raw_received_at"),
                rs.getLong("target_id"),
                rs.getString("log_type_code"),
                rs.getString("event_type_code"),
                rs.getString("source_ip"),
                rs.getString("dest_ip"),
                (Integer) rs.getObject("dest_port"),
                rs.getString("user_account"),
                rs.getString("host_name"),
                rs.getString("severity"),
                rs.getString("extra"));
    }

    static Instant instant(ResultSet rs, String column) throws SQLException {
        OffsetDateTime t = rs.getObject(column, OffsetDateTime.class);
        return t == null ? null : t.toInstant();
    }

    public static OffsetDateTime utc(Instant t) {
        return t == null ? null : OffsetDateTime.ofInstant(t, ZoneOffset.UTC);
    }
}
