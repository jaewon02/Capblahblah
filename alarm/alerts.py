"""경보 관리 (WBS 5.4 · No 142–152).

기능-테이블 매핑 '경보 생성 · 처리 · 오탐': C alert · alert_history / R alert · alert_policy / U alert
"""
from datetime import date, datetime, time, timedelta

from .common import KST, ApiError, current_user_id, iso, truncate

# 경보 처리 상태: 미확인 → 확인 → 처리 완료 (No 147–148). 오탐 여부는 별도 컬럼.
STATUSES = ("NEW", "ACK", "RESOLVED")
NEXT_STATUS = {"NEW": "ACK", "ACK": "RESOLVED", "RESOLVED": None}

# alert_history.action 값 (명세서: STATUS/FALSE_POSITIVE/ASSIGN/COMMENT)
ACTION_STATUS = "STATUS"
ACTION_FALSE_POSITIVE = "FALSE_POSITIVE"


def create_from_threat(conn, threat_id, severity, title):
    """위협 이벤트로부터 경보 자동 생성 (No 143–144). 탐지 엔진 트랜잭션 안에서 호출.

    alert_policy(등급별 1행)의 alert_mode 에 따라
      IMMEDIATE — 즉시 생성 / NONE — 생성 안 함 /
      THRESHOLD — 같은 등급 위협 이벤트가 threshold_window_sec 안에 threshold_count 건 이상이면 생성
    생성한 alert_id, 생성하지 않았으면 None 을 돌려준다.
    """
    policy = conn.execute(
        "SELECT alert_mode, threshold_count, threshold_window_sec FROM alert_policy WHERE severity = %s",
        (severity,)).fetchone()
    if policy is None or policy["alert_mode"] == "NONE":
        return None
    if policy["alert_mode"] == "THRESHOLD":
        count, window_sec = policy["threshold_count"], policy["threshold_window_sec"]
        if count is None or window_sec is None:
            return None
        recent = conn.execute(
            """
            SELECT count(*) AS n FROM threat_event
             WHERE severity = %s AND detected_at >= now() - make_interval(secs => %s)
            """, (severity, window_sec)).fetchone()["n"]
        if recent < count:
            return None

    # alert_no = ALT-시퀀스 (명세서: 예 ALT-0091, 시퀀스 기반, 접미사 금지)
    alert_id = conn.execute("SELECT nextval(pg_get_serial_sequence('alert', 'alert_id')) AS id").fetchone()["id"]
    conn.execute(
        """
        INSERT INTO alert (alert_id, alert_no, threat_id, severity, title)
        OVERRIDING SYSTEM VALUE
        VALUES (%s, %s, %s, %s, %s)
        """, (alert_id, f"ALT-{alert_id:04d}", threat_id, severity, truncate(title, 300)))
    # 시스템 자동 생성 → actor_id NULL
    conn.execute("INSERT INTO alert_history (alert_id, action, from_value, to_value) VALUES (%s, %s, NULL, %s)",
                 (alert_id, ACTION_STATUS, "NEW"))
    return alert_id


# ───────────── 검색 ─────────────

def parse_search(args):
    """검색 조건 (No 151–152). 날짜는 KST 기준, 비어 있는 항목은 조건에서 제외.

    args: request.args 같은 dict. 잘못된 값이면 ApiError(400).
    """
    status = args.get("status") or None
    if status is not None and status not in STATUSES:
        raise ApiError.bad_request(f"알 수 없는 상태입니다: {status}")
    severity = args.get("severity") or None
    if severity is not None and severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        raise ApiError.bad_request(f"알 수 없는 위험 등급입니다: {severity}")
    fp = args.get("falsePositive")
    false_positive = None if fp in (None, "") else str(fp).lower() == "true"
    return {
        "status": status,
        "false_positive": false_positive,
        "severity": severity,
        "from": _date(args.get("from"), "시작일"),
        "to": _date(args.get("to"), "종료일"),
    }


def _date(s, label):
    if not s:
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        raise ApiError.bad_request(f"{label} 형식은 YYYY-MM-DD 입니다.") from None


def _where(cond):
    clauses, args = [], []
    if cond.get("status"):
        clauses.append("a.status = %s")
        args.append(cond["status"])
    if cond.get("false_positive") is not None:
        clauses.append("a.is_false_positive = %s")
        args.append(cond["false_positive"])
    if cond.get("severity"):
        clauses.append("a.severity = %s")
        args.append(cond["severity"])
    if cond.get("from"):
        clauses.append("a.created_at >= %s")
        args.append(datetime.combine(cond["from"], time.min, KST))
    if cond.get("to"):
        # 종료일 당일 포함
        clauses.append("a.created_at < %s")
        args.append(datetime.combine(cond["to"] + timedelta(days=1), time.min, KST))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


_SELECT = """
    SELECT a.*, t.threat_no, r.rule_id, r.name AS rule_name
      FROM alert a
      LEFT JOIN threat_event t ON t.threat_id = a.threat_id
      LEFT JOIN detection_rule r ON r.rule_id = t.rule_id
"""


def search(conn, cond, page=0, size=50):
    """경보 목록 · 검색. 최신순 정렬 (No 146, 152)."""
    page, size = max(page, 0), min(max(size, 1), 200)
    where, args = _where(cond)
    total = conn.execute(f"SELECT count(*) AS n FROM alert a{where}", args).fetchone()["n"]
    rows = conn.execute(
        f"{_SELECT}{where} ORDER BY a.created_at DESC, a.alert_id DESC LIMIT %s OFFSET %s",
        [*args, size, page * size]).fetchall()
    return {"content": [_to_response(r) for r in rows], "totalElements": total, "page": page, "size": size}


def summary(conn, cond):
    """상태별 건수. 위험 등급 · 기간 조건은 적용하고 상태 · 오탐 조건은 무시."""
    base = {"severity": cond.get("severity"), "from": cond.get("from"), "to": cond.get("to")}
    where, args = _where(base)
    row = conn.execute(
        f"""
        SELECT count(*) AS total,
               count(*) FILTER (WHERE a.status = 'NEW') AS new_count,
               count(*) FILTER (WHERE a.status = 'ACK') AS ack_count,
               count(*) FILTER (WHERE a.status = 'RESOLVED') AS resolved_count,
               count(*) FILTER (WHERE a.is_false_positive) AS fp_count
          FROM alert a{where}
        """, args).fetchone()
    return {
        "total": row["total"],
        "newCount": row["new_count"],
        "ackCount": row["ack_count"],
        "resolvedCount": row["resolved_count"],
        "falsePositiveCount": row["fp_count"],
    }


def get(conn, alert_id):
    row = conn.execute(f"{_SELECT} WHERE a.alert_id = %s", (alert_id,)).fetchone()
    if row is None:
        raise ApiError.not_found("경보")
    return _to_response(row)


def histories(conn, alert_id):
    _find(conn, alert_id)
    rows = conn.execute(
        "SELECT * FROM alert_history WHERE alert_id = %s ORDER BY created_at, history_id", (alert_id,)).fetchall()
    return [{
        "historyId": h["history_id"],
        "alertId": h["alert_id"],
        "action": h["action"],
        "fromValue": h["from_value"],
        "toValue": h["to_value"],
        "comment": h["comment"],
        "actorId": h["actor_id"],  # 시스템 자동이면 None
        "createdAt": iso(h["created_at"]),
    } for h in rows]


# ───────────── 처리 ─────────────

def change_status(conn, alert_id, target):
    """상태는 한 단계씩만 진행: 미확인 → 확인 → 처리 완료 (No 148)."""
    if target not in STATUSES:
        raise ApiError.bad_request("변경할 상태를 선택하세요.")
    current = _find(conn, alert_id, lock=True)["status"]
    if NEXT_STATUS[current] != target:
        raise ApiError(409, f"상태는 미확인 → 확인 → 처리 완료 순서로만 바꿀 수 있습니다. (현재: {current})")

    conn.execute(
        """
        UPDATE alert SET status = %s, updated_at = now(),
               acked_at = CASE WHEN %s = 'ACK' THEN now() ELSE acked_at END,
               resolved_at = CASE WHEN %s = 'RESOLVED' THEN now() ELSE resolved_at END
         WHERE alert_id = %s
        """, (target, target, target, alert_id))
    _history(conn, alert_id, ACTION_STATUS, current, target, None)
    return get(conn, alert_id)


def set_false_positive(conn, alert_id, false_positive, comment):
    """오탐 지정 · 해제. 상태와 별개로 관리하고 내역을 남긴다 (No 150)."""
    if comment is not None and len(comment) > 1000:
        raise ApiError.bad_request("사유는 1000자 이하로 입력하세요.")
    alert = _find(conn, alert_id, lock=True)
    if alert["is_false_positive"] == false_positive:
        return get(conn, alert_id)
    conn.execute("UPDATE alert SET is_false_positive = %s, updated_at = now() WHERE alert_id = %s",
                 (false_positive, alert_id))
    _history(conn, alert_id, ACTION_FALSE_POSITIVE,
             str(not false_positive).lower(), str(false_positive).lower(), comment)
    return get(conn, alert_id)


def _find(conn, alert_id, lock=False):
    row = conn.execute("SELECT * FROM alert WHERE alert_id = %s" + (" FOR UPDATE" if lock else ""),
                       (alert_id,)).fetchone()
    if row is None:
        raise ApiError.not_found("경보")
    return row


def _history(conn, alert_id, action, from_value, to_value, comment):
    comment = comment.strip() if comment and comment.strip() else None
    conn.execute(
        """
        INSERT INTO alert_history (alert_id, action, from_value, to_value, comment, actor_id)
        VALUES (%s, %s, %s, %s, %s, %s)
        """, (alert_id, action, from_value, to_value, comment, current_user_id()))


def _to_response(r):
    return {
        "alertId": r["alert_id"],
        "alertNo": r["alert_no"],
        "createdAt": iso(r["created_at"]),
        "severity": r["severity"],
        "title": r["title"],
        "threatId": r["threat_id"],
        "threatNo": r["threat_no"],
        "ruleId": r["rule_id"],
        "ruleName": r["rule_name"],
        "status": r["status"],
        "falsePositive": r["is_false_positive"],
        "ackedAt": iso(r["acked_at"]),
        "resolvedAt": iso(r["resolved_at"]),
    }
