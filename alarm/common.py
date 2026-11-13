"""공통: 오류, 위험 등급, 시간대, 현재 사용자, 관리자 작업 이력."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from flask import has_request_context, request

from . import db

KST = ZoneInfo("Asia/Seoul")

# 위험 등급. 높은 순서 (화면 선택 목록 순서와 같다)
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # INFO=0 … CRITICAL=4


def max_severity(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if _RANK[a] >= _RANK[b] else b


class ApiError(Exception):
    """API 오류. 응답은 {"message": "..."} 형식 (화면은 message 를 그대로 표시)."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message

    @classmethod
    def not_found(cls, what):
        return cls(404, f"{what}을(를) 찾을 수 없습니다.")

    @classmethod
    def bad_request(cls, message):
        return cls(400, message)


def now_utc():
    return datetime.now(timezone.utc)


def blank_to_none(s):
    if s is None:
        return None
    s = str(s).strip()
    return s or None


def truncate(s, n):
    return s if s is None or len(s) <= n else s[:n]


# ───────────── 현재 사용자 ─────────────
# TODO: WBS 3.2(로그인 · 인증 · 세션) 완료 후 admin_session 의 user_id 를 반환하도록 교체.
#       그 전까지 admin_user 행이 없으므로 user_id 컬럼(created_by, actor_id 등)에는 NULL 이 기록된다.

def current_user_id():
    return None


def client_ip():
    """요청 IP (admin_audit_log.client_ip). 요청 밖(탐지 스레드)에서는 None."""
    return request.remote_addr if has_request_context() else None


# ───────────── 관리자 작업 이력 (TB_04, INSERT 전용) ─────────────
AUDIT_CREATE = "CREATE"
AUDIT_UPDATE = "UPDATE"
AUDIT_DELETE = "DELETE"


def audit(conn, menu, action, target_table, target_id, before, after, summary):
    """호출한 쪽 트랜잭션 안에서 기록된다. 업무 변경이 롤백되면 이력도 함께 롤백."""
    conn.execute(
        """
        INSERT INTO admin_audit_log (user_id, menu, action, target_table, target_id,
                                     before_value, after_value, summary, client_ip)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::inet)
        """,
        (current_user_id(), menu, action, target_table,
         None if target_id is None else str(target_id),
         db.jsonb(_json_safe(before)), db.jsonb(_json_safe(after)),
         truncate(summary, 500), client_ip()),
    )


def _json_safe(value):
    """datetime 등을 JSONB 에 넣을 수 있는 값으로 바꾼다."""
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, datetime):
        return iso(value)
    return value


def iso(t):
    """UTC ISO-8601 문자열 (예: 2026-11-10T07:41:43.123Z)."""
    if t is None:
        return None
    return t.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
