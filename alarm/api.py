"""JSON API (/api/**). 오류는 {"message": "..."} 형식."""
import psycopg
from flask import Blueprint, current_app, jsonify, request
from psycopg_pool import PoolTimeout
from werkzeug.exceptions import HTTPException

from . import alerts, db, rules, threats
from .common import ApiError

bp = Blueprint("api", __name__, url_prefix="/api")


def _body():
    data = request.get_json(silent=True)
    if data is None:
        raise ApiError.bad_request("입력값을 확인하세요.")
    return data


def _int_arg(name, default=None):
    v = request.args.get(name)
    if v in (None, ""):
        return default
    try:
        return int(v)
    except ValueError:
        raise ApiError.bad_request(f"{name} 값은 숫자여야 합니다.") from None


# ───────────── 공통 코드 (규칙 등록 화면의 선택 목록) ─────────────

def log_types(conn):
    rows = conn.execute("SELECT * FROM log_type ORDER BY sort_order, log_type_code").fetchall()
    return [{"logTypeCode": r["log_type_code"], "name": r["name"], "sortOrder": r["sort_order"]} for r in rows]


def event_types(conn):
    rows = conn.execute("SELECT * FROM event_type ORDER BY log_type_code, event_type_code").fetchall()
    return [{
        "eventTypeCode": r["event_type_code"], "name": r["name"], "logTypeCode": r["log_type_code"],
        "attackType": r["attack_type"], "mitreTechnique": r["mitre_technique"],
        "defaultSeverity": r["default_severity"],
    } for r in rows]


@bp.get("/codes/log-types")
def api_log_types():
    with db.transaction() as conn:
        return jsonify(log_types(conn))


@bp.get("/codes/event-types")
def api_event_types():
    with db.transaction() as conn:
        return jsonify(event_types(conn))


# ───────────── 탐지 규칙 (5.1) ─────────────

@bp.get("/rules")
def rule_list():
    with db.transaction() as conn:
        return jsonify(rules.list_rules(conn))


@bp.get("/rules/<int:rule_id>")
def rule_get(rule_id):
    with db.transaction() as conn:
        return jsonify(rules.get_rule(conn, rule_id))


@bp.post("/rules")
def rule_create():
    body = _body()
    with db.transaction() as conn:
        return jsonify(rules.create_rule(conn, body)), 201


@bp.put("/rules/<int:rule_id>")
def rule_update(rule_id):
    body = _body()
    with db.transaction() as conn:
        return jsonify(rules.update_rule(conn, rule_id, body))


@bp.patch("/rules/<int:rule_id>/active")
def rule_active(rule_id):
    active = _body().get("active")
    if not isinstance(active, bool):
        raise ApiError.bad_request("active 값은 true 또는 false 여야 합니다.")
    with db.transaction() as conn:
        return jsonify(rules.set_active(conn, rule_id, active))


@bp.delete("/rules/<int:rule_id>")
def rule_delete(rule_id):
    with db.transaction() as conn:
        rules.delete_rule(conn, rule_id)
    return "", 204


# ───────────── 탐지 결과 (5.3) ─────────────

@bp.get("/threats")
def threat_list():
    with db.transaction() as conn:
        return jsonify(threats.search(
            conn, rule_id=_int_arg("ruleId"), severity=request.args.get("severity") or None,
            page=_int_arg("page", 0), size=_int_arg("size", 50)))


@bp.get("/threats/<int:threat_id>")
def threat_detail(threat_id):
    with db.transaction() as conn:
        return jsonify(threats.detail(conn, threat_id))


# ───────────── 경보 (5.4) ─────────────

@bp.get("/alerts")
def alert_list():
    """예: GET /api/alerts?status=NEW&severity=HIGH&from=2026-11-23&to=2026-11-24 (날짜는 KST)"""
    cond = alerts.parse_search(request.args)
    with db.transaction() as conn:
        return jsonify(alerts.search(conn, cond, _int_arg("page", 0), _int_arg("size", 50)))


@bp.get("/alerts/summary")
def alert_summary():
    cond = alerts.parse_search(request.args)
    with db.transaction() as conn:
        return jsonify(alerts.summary(conn, cond))


@bp.get("/alerts/<int:alert_id>")
def alert_get(alert_id):
    with db.transaction() as conn:
        return jsonify(alerts.get(conn, alert_id))


@bp.get("/alerts/<int:alert_id>/history")
def alert_history(alert_id):
    with db.transaction() as conn:
        return jsonify(alerts.histories(conn, alert_id))


@bp.patch("/alerts/<int:alert_id>/status")
def alert_status(alert_id):
    status = _body().get("status")
    with db.transaction() as conn:
        return jsonify(alerts.change_status(conn, alert_id, status))


@bp.patch("/alerts/<int:alert_id>/false-positive")
def alert_false_positive(alert_id):
    body = _body()
    fp, comment = body.get("falsePositive", False), body.get("comment")
    if not isinstance(fp, bool) or (comment is not None and not isinstance(comment, str)):
        raise ApiError.bad_request("입력값을 확인하세요.")
    with db.transaction() as conn:
        return jsonify(alerts.set_false_positive(conn, alert_id, fp, comment))


# ───────────── 오류 응답 ─────────────

@bp.errorhandler(ApiError)
def handle_api_error(e):
    return jsonify(message=e.message), e.status


@bp.errorhandler(Exception)
def handle_unexpected(e):
    if isinstance(e, HTTPException):
        return jsonify(message=e.description or e.name), e.code
    if isinstance(e, (PoolTimeout, psycopg.OperationalError)):
        current_app.logger.error("DB 연결 실패: %s", e)
        return jsonify(message="데이터베이스에 연결할 수 없습니다. PostgreSQL 실행 여부와 "
                               "환경변수 DB_PASSWORD(siem 계정 비밀번호)를 확인하십시오."), 503
    current_app.logger.exception("API 처리 중 오류")
    return jsonify(message="서버 오류가 발생했습니다."), 500
