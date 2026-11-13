"""normalized_event · raw_log 조회 (파티션 테이블이라 복합 PK · 파티션 키 조건을 직접 다룬다).

기능-테이블 매핑 '탐지 실행 · 결과': R normalized_event, U normalized_event(severity).
"""

COLUMNS = """
    event_id, event_time, raw_log_id, raw_received_at, target_id, log_type_code, event_type_code,
    host(source_ip) AS source_ip, host(dest_ip) AS dest_ip, dest_port, user_account, host_name,
    severity, extra
"""


def find_after(conn, last_event_id, limit):
    """탐지 엔진: 마지막 처리 ID 이후의 신규 이벤트 (event_id 는 단일 시퀀스라 파티션과 무관하게 증가)."""
    return conn.execute(
        f"SELECT {COLUMNS} FROM normalized_event WHERE event_id > %s ORDER BY event_id LIMIT %s",
        (last_event_id, limit)).fetchall()


def cursor_since(conn, since):
    """기동 시 처리 시작 위치: 이 시각 이후 이벤트 중 가장 작은 ID - 1. 없으면 현재 최대 ID."""
    row = conn.execute("SELECT min(event_id) AS v FROM normalized_event WHERE event_time >= %s", (since,)).fetchone()
    if row["v"] is not None:
        return row["v"] - 1
    row = conn.execute("SELECT max(event_id) AS v FROM normalized_event").fetchone()
    return row["v"] or 0


def find_in_window(conn, start, end, event_type_code, log_type_code):
    """반복 행위 탐지: 시간 창 안의 이벤트. 이벤트 유형 · 로그 유형이 지정된 경우만 조건에 넣는다."""
    sql = f"SELECT {COLUMNS} FROM normalized_event WHERE event_time BETWEEN %s AND %s"
    args = [start, end]
    if event_type_code is not None:
        sql += " AND event_type_code = %s"
        args.append(event_type_code)
    if log_type_code is not None:
        sql += " AND log_type_code = %s"
        args.append(log_type_code)
    return conn.execute(sql + " ORDER BY event_time", args).fetchall()


def update_severity(conn, event_id, event_time, severity):
    """탐지된 이벤트에 위협 이벤트 등급 반영 (명세서: 검색용 반영 값)."""
    conn.execute("UPDATE normalized_event SET severity = %s WHERE event_id = %s AND event_time = %s",
                 (severity, event_id, event_time))


def related_logs(conn, threat_id, limit):
    """위협 이벤트의 관련 로그 원문 (최근순). threat_event_link → normalized_event → raw_log"""
    return conn.execute(
        """
        SELECT l.event_id, l.event_time, ne.event_type_code, ne.host_name,
               host(ne.source_ip) AS source_ip, ne.user_account, r.raw_message
          FROM threat_event_link l
          JOIN normalized_event ne ON ne.event_id = l.event_id AND ne.event_time = l.event_time
          LEFT JOIN raw_log r ON r.raw_log_id = ne.raw_log_id AND r.received_at = ne.raw_received_at
         WHERE l.threat_id = %s
         ORDER BY l.event_time DESC
         LIMIT %s
        """, (threat_id, limit)).fetchall()


def count_links(conn, threat_id):
    return conn.execute("SELECT count(*) AS n FROM threat_event_link WHERE threat_id = %s",
                        (threat_id,)).fetchone()["n"]
