"""탐지 결과 생성 (WBS 5.2.3) · 조회 (WBS 5.3).

기능-테이블 매핑 '탐지 실행 · 결과': C threat_event · threat_event_link / U normalized_event(severity)
"""
from . import alerts, db, events
from .common import SEVERITIES, ApiError, KST, iso, max_severity, now_utc, truncate

MAX_LINKS = 500     # 위협 1건에 연결하는 근거 이벤트 최대 수 (대량 공격 시 링크 폭증 방지)
DETAIL_LOGS = 20    # 상세 화면에 보여줄 관련 로그 수


def create(conn, rule, group_key, matched, alert_title, evidence):
    """조건 충족 시 위협 이벤트 생성 (No 136).

    threat_event 저장 → threat_event_link 로 관련 로그 연결 → normalized_event.severity 반영 → 경보 생성 연계.
    evidence: {"cond": 조건 요약, "observed": 관측값} (명세서 예시 형식, 탐지 당시 조건 스냅샷)
    """
    ordered = sorted(matched, key=lambda e: e["event_time"])
    first, last = ordered[0], ordered[-1]
    severity = rule["severity"]

    # threat_no = EVT-yyyyMMdd(KST)-시퀀스 (명세서 예: EVT-20261020-0412)
    threat_id = conn.execute(
        "SELECT nextval(pg_get_serial_sequence('threat_event', 'threat_id')) AS id").fetchone()["id"]
    threat_no = f"EVT-{now_utc().astimezone(KST):%Y%m%d}-{threat_id:04d}"

    conn.execute(
        """
        INSERT INTO threat_event (threat_id, threat_no, rule_id, rule_version, first_event_time, last_event_time,
                                  group_key, source_ip, user_account, target_id, log_type_code, event_count,
                                  severity, original_severity, evidence)
        OVERRIDING SYSTEM VALUE
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::inet, %s, %s, %s, %s, %s, %s, %s)
        """,
        (threat_id, threat_no, rule["rule_id"], rule["version"], first["event_time"], last["event_time"],
         truncate(group_key, 200), last["source_ip"], last["user_account"], last["target_id"],
         rule["log_type_code"] or last["log_type_code"], len(ordered), severity, severity, db.jsonb(evidence)))

    # 최근 이벤트 위주로 연결
    to_link = ordered[-MAX_LINKS:]
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO threat_event_link (threat_id, event_id, event_time, raw_log_id) VALUES (%s, %s, %s, %s)",
            [(threat_id, e["event_id"], e["event_time"], e["raw_log_id"]) for e in to_link])

    # 정규화 이벤트에 검색용 위험 등급 반영 (원천은 threat_event.severity)
    for e in to_link:
        merged = max_severity(e["severity"], severity)
        if merged != e["severity"]:
            events.update_severity(conn, e["event_id"], e["event_time"], merged)
            e["severity"] = merged

    alerts.create_from_threat(conn, threat_id, severity, alert_title)
    return threat_id


def already_linked(conn, rule_id, event_id):
    """이 이벤트가 이미 이 규칙의 위협 이벤트 근거로 연결돼 있는지 (재기동 후 재처리 시 중복 방지)."""
    return conn.execute(
        """
        SELECT EXISTS (SELECT 1 FROM threat_event_link l JOIN threat_event t ON t.threat_id = l.threat_id
                        WHERE l.event_id = %s AND t.rule_id = %s) AS b
        """, (event_id, rule_id)).fetchone()["b"]


def detected_since(conn, rule_id, group_key, since):
    """같은 규칙 · 같은 그룹 키로 since 이후의 이벤트까지 이미 탐지했는지 (중복 억제 · 재처리 중복 방지)."""
    return conn.execute(
        """
        SELECT EXISTS (SELECT 1 FROM threat_event
                        WHERE rule_id = %s AND group_key IS NOT DISTINCT FROM %s::varchar
                          AND last_event_time >= %s) AS b
        """, (rule_id, truncate(group_key, 200), since)).fetchone()["b"]


# ───────────── 조회 ─────────────

_SELECT = """
    SELECT t.*, r.name AS rule_name
      FROM threat_event t
      LEFT JOIN detection_rule r ON r.rule_id = t.rule_id
"""


def search(conn, rule_id=None, severity=None, page=0, size=50):
    if severity is not None and severity not in SEVERITIES:
        raise ApiError.bad_request(f"알 수 없는 위험 등급입니다: {severity}")
    page, size = max(page, 0), min(max(size, 1), 200)
    clauses, args = [], []
    if rule_id is not None:
        clauses.append("t.rule_id = %s")
        args.append(rule_id)
    if severity is not None:
        clauses.append("t.severity = %s")
        args.append(severity)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total = conn.execute(f"SELECT count(*) AS n FROM threat_event t{where}", args).fetchone()["n"]
    rows = conn.execute(
        f"{_SELECT}{where} ORDER BY t.detected_at DESC, t.threat_id DESC LIMIT %s OFFSET %s",
        [*args, size, page * size]).fetchall()
    return {"content": [_to_item(r) for r in rows], "totalElements": total, "page": page, "size": size}


def detail(conn, threat_id):
    """탐지 근거 및 관련 로그 (No 141)."""
    t = conn.execute(f"{_SELECT} WHERE t.threat_id = %s", (threat_id,)).fetchone()
    if t is None:
        raise ApiError.not_found("위협 이벤트")

    a = conn.execute("SELECT alert_id, alert_no, status, is_false_positive FROM alert WHERE threat_id = %s",
                     (threat_id,)).fetchone()
    alert_ref = None if a is None else {
        "alertId": a["alert_id"], "alertNo": a["alert_no"],
        "status": a["status"], "falsePositive": a["is_false_positive"],
    }
    logs = [{
        "eventId": r["event_id"],
        "eventTime": iso(r["event_time"]),
        "eventTypeCode": r["event_type_code"],
        "hostName": r["host_name"],
        "sourceIp": r["source_ip"],
        "userAccount": r["user_account"],
        "raw": r["raw_message"],  # raw_log.raw_message 원문
    } for r in events.related_logs(conn, threat_id, DETAIL_LOGS)]

    evidence = t["evidence"] if isinstance(t["evidence"], dict) else None
    return {
        "threat": _to_item(t),
        "ruleVersion": t["rule_version"],
        "originalSeverity": t["original_severity"],
        "firstEventTime": iso(t["first_event_time"]),
        "lastEventTime": iso(t["last_event_time"]),
        "evidence": None if evidence is None else {"cond": evidence.get("cond"), "observed": evidence.get("observed")},
        "alert": alert_ref,
        "linkedLogCount": events.count_links(conn, threat_id),
        "logs": logs,
    }


def _to_item(t):
    """탐지된 위협 목록 한 줄 (No 139: 탐지 시각, 규칙, 위험 등급)."""
    return {
        "threatId": t["threat_id"],
        "threatNo": t["threat_no"],
        "detectedAt": iso(t["detected_at"]),
        "ruleId": t["rule_id"],
        "ruleName": t["rule_name"],
        "groupKey": t["group_key"],
        "severity": t["severity"],
        "eventCount": t["event_count"],
    }
