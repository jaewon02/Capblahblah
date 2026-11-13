"""탐지 규칙 관리 (WBS 5.1 · No 118–129).

기능-테이블 매핑: C detection_rule · admin_audit_log / R · U detection_rule / D detection_rule(논리)

detection_rule JSONB 컬럼 형식 (명세서 예시)
    condition_expr: {"all":[{"field":"extra.USER","op":"eq","value":"root"}]}   (모두 만족 시 일치)
    exceptions    : {"source_ip":["192.0.2.0/28"],"user_account":["svc-scanner"]}

field: normalized_event 컬럼명(event_type_code, log_type_code, target_id, source_ip, dest_ip, dest_port,
       user_account, host_name, event_time) 또는 extra.<키>
op   : eq, ne, contains, regex, in(value = 배열), between / not_between(숫자 "a-b"),
       hour_between / hour_not_between(event_time 의 KST 시각, "9-18" = 09:00~17:59)
"""
import re

from . import db
from .common import (
    AUDIT_CREATE, AUDIT_DELETE, AUDIT_UPDATE, SEVERITIES, ApiError, audit, blank_to_none,
    current_user_id, iso,
)

MENU = "위협 탐지 규칙"
TABLE = "detection_rule"

DETECT_METHODS = ("CONDITION", "THRESHOLD")  # 조건 기반 / 반복 행위
METHOD_LABELS = {"CONDITION": "조건 기반", "THRESHOLD": "반복 행위"}

# detection_rule.group_by (명세서: SOURCE_IP/USER_ACCOUNT/TARGET)
GROUP_LABELS = {"SOURCE_IP": "출발지 IP", "USER_ACCOUNT": "사용자 계정", "TARGET": "수집 대상"}

FIELDS = {"event_type_code", "log_type_code", "target_id", "source_ip", "dest_ip", "dest_port",
          "user_account", "host_name", "event_time"}
OPS = {"eq", "ne", "contains", "regex", "in", "between", "not_between", "hour_between", "hour_not_between"}
HOUR_OPS = {"hour_between", "hour_not_between"}
RANGE = re.compile(r"\s*(-?\d+)\s*-\s*(-?\d+)\s*")


def is_valid_field(field):
    return field in FIELDS or (field.startswith("extra.") and len(field) > len("extra."))


def as_text(value):
    """JSON 값을 문자열로 (배열 · null 이면 None). true → "true" (Jackson asText 와 같게)."""
    if value is None or isinstance(value, (list, dict)):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def read_conditions(expr):
    if not expr:
        return []
    return expr.get("all") or []


def clean_exceptions(exceptions):
    """비어 있는 항목을 빼고, 다 비면 None (NULL 저장)."""
    if not exceptions:
        return None
    cleaned = {k: v for k, v in exceptions.items() if v}
    return cleaned or None


# ───────────── 조건 요약 문자열 ─────────────

def window_text(sec):
    if sec is None:
        return "-"
    if sec % 3600 == 0:
        return f"{sec // 3600}시간"
    if sec % 60 == 0:
        return f"{sec // 60}분"
    return f"{sec}초"


def _value_text(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(as_text(v) or "" for v in value)
    return as_text(value) or ""


def describe_condition(c):
    f, op, v = c["field"], c["op"], _value_text(c.get("value"))
    return {
        "eq": f"{f}={v}",
        "ne": f"{f}≠{v}",
        "in": f"{f} ∈ {{{v}}}",
        "contains": f'{f} contains "{v}"',
        "regex": f"{f} ~ /{v}/",
        "between": f"{f} ∈ [{v.replace('-', '–')}]",
        "not_between": f"{f} ∉ [{v.replace('-', '–')}]",
        "hour_between": f"시각 ∈ [{v.replace('-', '–')}시]",
        "hour_not_between": f"시각 ∉ [{v.replace('-', '–')}시]",
    }.get(op, f"{f} {op} {v}")


def describe(rule, conditions):
    """규칙 조건을 사람이 읽는 한 줄로. 예: "ssh_auth_failed > 10회 / 5분 · 출발지 IP" """
    parts = []
    if rule["event_type_code"]:
        parts.append(rule["event_type_code"])
    parts += [describe_condition(c) for c in conditions]
    base = " AND ".join(parts) if parts else "(모든 이벤트)"
    if rule["detect_method"] == "THRESHOLD":
        group = GROUP_LABELS.get(rule["group_by"], rule["group_by"])
        return f"{base} > {rule['threshold_count']}회 / {window_text(rule['time_window_sec'])} · {group}"
    return base


# ───────────── 조회 ─────────────

def to_response(r):
    conditions = read_conditions(r["condition_expr"])
    return {
        "ruleId": r["rule_id"],
        "name": r["name"],
        "description": r["description"],
        "detectMethod": r["detect_method"],
        "logTypeCode": r["log_type_code"],
        "eventTypeCode": r["event_type_code"],
        "conditions": conditions,
        "groupBy": r["group_by"],
        "timeWindowSec": r["time_window_sec"],
        "thresholdCount": r["threshold_count"],
        "severity": r["severity"],
        "suppressSec": r["suppress_sec"],
        "exceptions": r["exceptions"] or {},
        "mitreTechnique": r["mitre_technique"],
        "active": r["is_active"],
        "version": r["version"],
        "conditionText": describe(r, conditions),  # 목록 · 탐지 근거 화면용 조건 요약
        "createdBy": r["created_by"],
        "createdAt": iso(r["created_at"]),
        "updatedBy": r["updated_by"],
        "updatedAt": iso(r["updated_at"]),
    }


def list_rules(conn):
    rows = conn.execute("SELECT * FROM detection_rule WHERE deleted_at IS NULL ORDER BY rule_id").fetchall()
    return [to_response(r) for r in rows]


def get_rule(conn, rule_id):
    return to_response(_find(conn, rule_id))


def active_rules(conn):
    """탐지 엔진: 활성 규칙만 적용 (No 129)."""
    return conn.execute(
        "SELECT * FROM detection_rule WHERE is_active AND deleted_at IS NULL ORDER BY rule_id").fetchall()


def _find(conn, rule_id, lock=False):
    row = conn.execute(
        "SELECT * FROM detection_rule WHERE rule_id = %s AND deleted_at IS NULL" + (" FOR UPDATE" if lock else ""),
        (rule_id,)).fetchone()
    if row is None:
        raise ApiError.not_found("탐지 규칙")
    return row


# ───────────── 등록 · 수정 · 활성화 · 삭제 ─────────────

def create_rule(conn, req):
    v = _validate(conn, req)
    row = conn.execute(
        """
        INSERT INTO detection_rule (name, description, detect_method, log_type_code, event_type_code,
                                    condition_expr, group_by, time_window_sec, threshold_count, severity,
                                    suppress_sec, exceptions, mitre_technique, is_active, version, created_by)
        VALUES (%(name)s, %(description)s, %(detect_method)s, %(log_type_code)s, %(event_type_code)s,
                %(condition_expr)s, %(group_by)s, %(time_window_sec)s, %(threshold_count)s, %(severity)s,
                %(suppress_sec)s, %(exceptions)s, %(mitre_technique)s, TRUE, 1, %(user)s)
        RETURNING *
        """,
        {**_params(v), "user": current_user_id()},
    ).fetchone()
    after = to_response(row)
    audit(conn, MENU, AUDIT_CREATE, TABLE, row["rule_id"], None, after, f"탐지 규칙 등록: {row['name']}")
    return after


def update_rule(conn, rule_id, req):
    """조건 변경 → version +1, 변경 내역을 관리자 이력에 기록 (No 125)."""
    v = _validate(conn, req)
    before = to_response(_find(conn, rule_id, lock=True))
    row = conn.execute(
        """
        UPDATE detection_rule
           SET name = %(name)s, description = %(description)s, detect_method = %(detect_method)s,
               log_type_code = %(log_type_code)s, event_type_code = %(event_type_code)s,
               condition_expr = %(condition_expr)s, group_by = %(group_by)s,
               time_window_sec = %(time_window_sec)s, threshold_count = %(threshold_count)s,
               severity = %(severity)s, suppress_sec = %(suppress_sec)s, exceptions = %(exceptions)s,
               mitre_technique = %(mitre_technique)s, version = version + 1,
               updated_by = %(user)s, updated_at = now()
         WHERE rule_id = %(rule_id)s
        RETURNING *
        """,
        {**_params(v), "user": current_user_id(), "rule_id": rule_id},
    ).fetchone()
    after = to_response(row)
    audit(conn, MENU, AUDIT_UPDATE, TABLE, rule_id, before, after,
          f"탐지 규칙 수정: {row['name']} (v{before['version']} → v{after['version']})")
    return after


def set_active(conn, rule_id, active):
    """활성화 / 비활성화 (No 129)."""
    rule = _find(conn, rule_id, lock=True)
    if rule["is_active"] == active:
        return to_response(rule)
    row = conn.execute(
        "UPDATE detection_rule SET is_active = %s, updated_by = %s, updated_at = now() WHERE rule_id = %s RETURNING *",
        (active, current_user_id(), rule_id),
    ).fetchone()
    audit(conn, MENU, AUDIT_UPDATE, TABLE, rule_id, {"is_active": not active}, {"is_active": active},
          f"탐지 규칙 {'활성화' if active else '비활성화'}: {row['name']}")
    return to_response(row)


def delete_rule(conn, rule_id):
    """논리 삭제 (No 127). 과거 탐지 근거 보존을 위해 행은 남긴다."""
    rule = _find(conn, rule_id, lock=True)
    before = to_response(rule)
    conn.execute(
        "UPDATE detection_rule SET deleted_at = now(), updated_by = %s, updated_at = now() WHERE rule_id = %s",
        (current_user_id(), rule_id),
    )
    audit(conn, MENU, AUDIT_DELETE, TABLE, rule_id, before, None, f"탐지 규칙 삭제: {rule['name']}")


def _params(v):
    return {
        "name": v["name"],
        "description": v["description"],
        "detect_method": v["detect_method"],
        "log_type_code": v["log_type_code"],
        "event_type_code": v["event_type_code"],
        "condition_expr": db.jsonb({"all": v["conditions"]}),
        "group_by": v["group_by"],
        "time_window_sec": v["time_window_sec"],
        "threshold_count": v["threshold_count"],
        "severity": v["severity"],
        "suppress_sec": v["suppress_sec"],
        "exceptions": db.jsonb(v["exceptions"]),
        "mitre_technique": v["mitre_technique"],
    }


# ───────────── 입력 검증 (길이 제한은 명세서 컬럼 길이와 같다) ─────────────

def _int(value, message):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ApiError.bad_request(message)
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise ApiError.bad_request(message) from None
    if f != int(f):
        raise ApiError.bad_request(message)
    return int(f)


def _str(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ApiError.bad_request("입력값을 확인하세요.")
    return value


def _validate(conn, req):
    """API 요청 본문(camelCase)을 검증해 저장할 값(snake_case)으로 바꾼다."""
    if not isinstance(req, dict):
        raise ApiError.bad_request("입력값을 확인하세요.")

    name = blank_to_none(_str(req.get("name")))
    if name is None:
        raise ApiError.bad_request("규칙 이름은 필수입니다.")
    if len(name) > 100:
        raise ApiError.bad_request("규칙 이름은 100자 이하로 입력하세요.")
    description = blank_to_none(_str(req.get("description")))
    if description and len(description) > 500:
        raise ApiError.bad_request("설명은 500자 이하로 입력하세요.")
    method = req.get("detectMethod")
    if method not in DETECT_METHODS:
        raise ApiError.bad_request("탐지 방식을 선택하세요.")
    severity = req.get("severity")
    if severity not in SEVERITIES:
        raise ApiError.bad_request("위험 등급을 선택하세요.")
    window = _int(req.get("timeWindowSec"), "시간 창은 정수로 입력하세요.")
    if window is not None and window <= 0:
        raise ApiError.bad_request("시간 창은 1초 이상이어야 합니다.")
    threshold = _int(req.get("thresholdCount"), "임계 횟수는 정수로 입력하세요.")
    if threshold is not None and threshold <= 0:
        raise ApiError.bad_request("임계 횟수는 1 이상이어야 합니다.")
    suppress = _int(req.get("suppressSec"), "중복 억제 시간은 정수로 입력하세요.")
    if suppress is not None and suppress < 0:
        raise ApiError.bad_request("중복 억제 시간은 0 이상이어야 합니다.")
    mitre = blank_to_none(_str(req.get("mitreTechnique")))
    if mitre and len(mitre) > 20:
        raise ApiError.bad_request("ATT&CK 기법은 20자 이하로 입력하세요.")

    log_type = blank_to_none(_str(req.get("logTypeCode")))
    event_type = blank_to_none(_str(req.get("eventTypeCode")))
    if log_type and not conn.execute("SELECT 1 FROM log_type WHERE log_type_code = %s", (log_type,)).fetchone():
        raise ApiError.bad_request(f"알 수 없는 로그 유형입니다: {log_type}")
    if event_type and not conn.execute(
            "SELECT 1 FROM event_type WHERE event_type_code = %s", (event_type,)).fetchone():
        raise ApiError.bad_request(f"알 수 없는 이벤트 유형입니다: {event_type}")
    group_by = blank_to_none(_str(req.get("groupBy")))
    if group_by and group_by not in GROUP_LABELS:
        raise ApiError.bad_request("그룹 기준은 SOURCE_IP, USER_ACCOUNT, TARGET 중 하나여야 합니다.")

    conditions = req.get("conditions") or []
    if not isinstance(conditions, list):
        raise ApiError.bad_request("입력값을 확인하세요.")
    conditions = [_validate_condition(c) for c in conditions]

    threshold_method = method == "THRESHOLD"
    if threshold_method:
        # 명세서 CHECK: THRESHOLD 이면 time_window_sec > 0 AND threshold_count > 0 AND group_by IS NOT NULL
        if group_by is None:
            raise ApiError.bad_request("반복 행위 탐지는 그룹 기준이 필요합니다.")
        if window is None:
            raise ApiError.bad_request("시간 창을 입력하세요.")
        if threshold is None:
            raise ApiError.bad_request("임계 횟수를 입력하세요.")
    elif event_type is None and not conditions:
        raise ApiError.bad_request("조건 기반 탐지는 이벤트 유형 또는 조건이 하나 이상 필요합니다.")

    exceptions = req.get("exceptions")
    if exceptions is not None:
        if not isinstance(exceptions, dict):
            raise ApiError.bad_request("입력값을 확인하세요.")
        for key, values in exceptions.items():
            if not is_valid_field(key) or key == "event_time":
                raise ApiError.bad_request(f"예외 조건에 쓸 수 없는 필드입니다: {key}")
            if values is not None and not (isinstance(values, list) and all(isinstance(x, str) for x in values)):
                raise ApiError.bad_request("예외 조건 값은 문자열 목록이어야 합니다.")

    return {
        "name": name,
        "description": description,
        "detect_method": method,
        "log_type_code": log_type,
        "event_type_code": event_type,
        "conditions": conditions,
        "group_by": group_by,
        "time_window_sec": window if threshold_method else None,
        "threshold_count": threshold if threshold_method else None,
        "severity": severity,
        "suppress_sec": suppress or 0,
        "exceptions": clean_exceptions(exceptions),
        "mitre_technique": mitre,
    }


def _validate_condition(c):
    if not isinstance(c, dict):
        raise ApiError.bad_request("입력값을 확인하세요.")
    field = blank_to_none(_str(c.get("field")))
    op = blank_to_none(_str(c.get("op")))
    value = c.get("value")
    if field is None:
        raise ApiError.bad_request("조건 필드를 입력하세요.")
    if op is None:
        raise ApiError.bad_request("조건 연산자를 선택하세요.")
    if not is_valid_field(field):
        raise ApiError.bad_request(f"지원하지 않는 조건 필드입니다: {field}")
    if op not in OPS:
        raise ApiError.bad_request(f"지원하지 않는 연산자입니다: {op}")
    hour_op = op in HOUR_OPS
    if hour_op != (field == "event_time"):
        raise ApiError.bad_request("발생 시각(event_time)은 시각 범위 연산자로만 비교할 수 있습니다.")

    if op == "in":
        if not isinstance(value, list) or not value:
            raise ApiError.bad_request("'목록 중 하나'는 값이 하나 이상 필요합니다.")
        return {"field": field, "op": op, "value": value}

    text = as_text(value)
    if text is None:
        raise ApiError.bad_request(f"조건 값을 입력하세요: {field}")
    if op == "regex":
        try:
            re.compile(text)
        except re.error:
            raise ApiError.bad_request(f"정규식 형식 오류: {text}") from None
    if (hour_op or op.endswith("between")) and not RANGE.fullmatch(text):
        raise ApiError.bad_request('범위는 "9-18" 형식으로 입력하세요.')
    return {"field": field, "op": op, "value": value}
