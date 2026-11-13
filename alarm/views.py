"""관리자 화면 (Jinja 템플릿). 목업 Rules.html · Alerts.html 기준.

화면은 서버에서 그리고, 처리(등록 · 수정 · 상태 변경 등)는 HTML 폼 POST → 처리 후 원래 화면으로 이동.
업무 처리는 API 와 같은 서비스 함수(rules · threats · alerts)를 쓴다.
"""
from urllib.parse import urlencode, urlsplit

from flask import Blueprint, flash, redirect, render_template, request, url_for

from . import alerts, db, rules, threats
from .api import event_types, log_types
from .common import SEVERITIES, ApiError

bp = Blueprint("views", __name__)

ALERT_PAGE_SIZE = 50
THREAT_LIST_SIZE = 100

# 다른 담당 영역 — 각 담당자가 화면 추가
PLACEHOLDERS = {
    "dashboard": ("대시보드", "3.10"),
    "collect": ("로그 수집 관리", "3.3"),
    "logs": ("로그 조회 · 파싱", "3.4 · 3.5"),
    "analysis": ("로그 분석 · 위험 등급", "3.7"),
    "reports": ("보고서", "3.11"),
    "settings": ("시스템 설정", "3.9"),
}


@bp.get("/")
def index():
    return redirect(url_for("views.rules_page"))


@bp.get("/<any(dashboard, collect, logs, analysis, reports, settings):menu>")
def placeholder(menu):
    title, wbs = PLACEHOLDERS[menu]
    return render_template("placeholder.html", menu=menu, title=title, wbs=wbs)


# ───────────── 위협 탐지 규칙 (탭1: 규칙 관리 5.1, 탭2: 탐지 결과 5.3) ─────────────

@bp.get("/rules")
def rules_page():
    tab = "results" if request.args.get("tab") == "results" else "rules"
    edit_id = request.args.get("edit", type=int)
    with db.transaction() as conn:
        if tab == "results":
            return _render_results(conn, request.args.get("threat", type=int))
        editing = None
        if edit_id is not None:
            try:
                editing = rules.get_rule(conn, edit_id)
            except ApiError as e:
                flash(e.message, "error")
        return _render_rules(conn, editing, form_from_rule(editing))


@bp.post("/rules")
def rule_create():
    form = dict(request.form)
    form["conditions"] = _conditions_from_form()
    try:
        with db.transaction() as conn:
            rule = rules.create_rule(conn, request_from_form(form))
    except ApiError as e:
        with db.transaction() as conn:
            return _render_rules(conn, None, form, error=e.message), 400
    flash(f"'{rule['name']}' 규칙을 등록했습니다.", "ok")
    return redirect(url_for("views.rules_page"))


@bp.post("/rules/<int:rule_id>")
def rule_update(rule_id):
    form = dict(request.form)
    form["conditions"] = _conditions_from_form()
    try:
        with db.transaction() as conn:
            rule = rules.update_rule(conn, rule_id, request_from_form(form))
    except ApiError as e:
        with db.transaction() as conn:
            try:
                editing = rules.get_rule(conn, rule_id)
            except ApiError:
                flash(e.message, "error")
                return redirect(url_for("views.rules_page"))
            return _render_rules(conn, editing, form, error=e.message), 400
    flash(f"'{rule['name']}' 규칙을 저장했습니다. (v{rule['version']})", "ok")
    return redirect(url_for("views.rules_page"))


@bp.post("/rules/<int:rule_id>/active")
def rule_active(rule_id):
    try:
        with db.transaction() as conn:
            rules.set_active(conn, rule_id, request.form.get("active") == "true")
    except ApiError as e:
        flash(e.message, "error")
    return redirect(_back(url_for("views.rules_page")))


@bp.post("/rules/<int:rule_id>/delete")
def rule_delete(rule_id):
    try:
        with db.transaction() as conn:
            rules.delete_rule(conn, rule_id)
        flash("규칙을 삭제했습니다. 삭제 내역은 관리자 이력에 기록됩니다.", "ok")
    except ApiError as e:
        flash(e.message, "error")
    return redirect(url_for("views.rules_page"))


def _render_rules(conn, editing, form, error=None):
    return render_template(
        "rules.html", menu="rules", tab="rules",
        rules=rules.list_rules(conn), editing=editing, form=form, form_error=error,
        log_types=log_types(conn), event_types=event_types(conn),
        method_labels=rules.METHOD_LABELS, group_labels=rules.GROUP_LABELS, severities=SEVERITIES,
    )


def _render_results(conn, threat_id):
    page = threats.search(conn, size=THREAT_LIST_SIZE)
    items = page["content"]
    if threat_id is None and items:
        threat_id = items[0]["threatId"]
    detail = None
    if threat_id is not None:
        try:
            detail = threats.detail(conn, threat_id)
        except ApiError as e:
            flash(e.message, "error")
    return render_template("rules.html", menu="rules", tab="results", items=items, detail=detail,
                           selected_id=threat_id, rule_count=len(rules.list_rules(conn)))


# 서버 조건 {field:"extra.COMMAND", value:[...]} ↔ 화면 {field:"extra.", extraKey:"COMMAND", value:"a, b"}

def form_from_rule(rule):
    if rule is None:
        # 시간 창 · 임계 횟수 기본값 = system_setting detect.default_window_sec(300) · detect.default_threshold(10)
        return {
            "name": "", "description": "", "detectMethod": "THRESHOLD", "logTypeCode": "", "eventTypeCode": "",
            "groupBy": "SOURCE_IP", "windowMin": "5", "thresholdCount": "10", "severity": "HIGH",
            "suppressMin": "0", "mitreTechnique": "", "conditions": [], "exceptIps": "", "exceptUsers": "",
        }
    ex = rule["exceptions"] or {}
    return {
        "name": rule["name"],
        "description": rule["description"] or "",
        "detectMethod": rule["detectMethod"],
        "logTypeCode": rule["logTypeCode"] or "",
        "eventTypeCode": rule["eventTypeCode"] or "",
        "groupBy": rule["groupBy"] or "",
        "windowMin": _num(rule["timeWindowSec"] / 60) if rule["timeWindowSec"] else "5",
        "thresholdCount": str(rule["thresholdCount"]) if rule["thresholdCount"] else "10",
        "severity": rule["severity"],
        "suppressMin": _num((rule["suppressSec"] or 0) / 60),
        "mitreTechnique": rule["mitreTechnique"] or "",
        "conditions": [{
            "field": "extra." if c["field"].startswith("extra.") else c["field"],
            "extraKey": c["field"][6:] if c["field"].startswith("extra.") else "",
            "op": c["op"],
            "value": ", ".join(rules.as_text(v) or "" for v in c["value"]) if isinstance(c.get("value"), list)
            else (rules.as_text(c.get("value")) or ""),
        } for c in rule["conditions"]],
        "exceptIps": ", ".join(ex.get("source_ip", [])),
        "exceptUsers": ", ".join(ex.get("user_account", [])),
    }


def _num(f):
    return str(int(f)) if f == int(f) else str(f)


def _split(s):
    return [v.strip() for v in (s or "").split(",") if v.strip()]


def _conditions_from_form():
    fields = request.form.getlist("cond_field")
    keys = request.form.getlist("cond_extra")
    ops = request.form.getlist("cond_op")
    values = request.form.getlist("cond_value")
    return [{"field": f, "extraKey": k, "op": o, "value": v} for f, k, o, v in zip(fields, keys, ops, values)]


def _number(s, message):
    s = (s or "").strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        raise ApiError.bad_request(message) from None


def request_from_form(form):
    """화면 폼 값 → API 요청 본문과 같은 형식."""
    threshold = form.get("detectMethod") == "THRESHOLD"
    window_min = _number(form.get("windowMin"), "시간 창은 숫자로 입력하세요.")
    count = _number(form.get("thresholdCount"), "임계 횟수는 숫자로 입력하세요.")
    suppress_min = _number(form.get("suppressMin"), "중복 억제 시간은 숫자로 입력하세요.")
    exceptions = {}
    if _split(form.get("exceptIps")):
        exceptions["source_ip"] = _split(form.get("exceptIps"))
    if _split(form.get("exceptUsers")):
        exceptions["user_account"] = _split(form.get("exceptUsers"))
    return {
        "name": form.get("name"),
        "description": form.get("description"),
        "detectMethod": form.get("detectMethod"),
        "logTypeCode": form.get("logTypeCode") or None,
        "eventTypeCode": form.get("eventTypeCode") or None,
        "conditions": [{
            "field": f"extra.{c['extraKey'].strip()}" if c["field"] == "extra." else c["field"],
            "op": c["op"],
            "value": _split(c["value"]) if c["op"] == "in" else c["value"],
        } for c in form["conditions"]],
        "groupBy": form.get("groupBy") or None,
        "timeWindowSec": round(window_min * 60) if threshold and window_min is not None else None,
        "thresholdCount": count if threshold else None,
        "severity": form.get("severity"),
        "suppressSec": round((suppress_min or 0) * 60),
        "exceptions": exceptions,
        "mitreTechnique": form.get("mitreTechnique") or None,
    }


# ───────────── 경보 관리 (No 142–152) ─────────────

# 상태 칩 → 검색 조건
CHIPS = [
    ("all", "전체", "total", {}),
    ("NEW", "미확인", "newCount", {"status": "NEW"}),
    ("ACK", "확인", "ackCount", {"status": "ACK"}),
    ("RESOLVED", "처리 완료", "resolvedCount", {"status": "RESOLVED"}),
    ("fp", "오탐", "falsePositiveCount", {"falsePositive": "true"}),
]


@bp.get("/alerts")
def alerts_page():
    chip = request.args.get("chip", "all")
    chip_params = next((c[3] for c in CHIPS if c[0] == chip), None)
    if chip_params is None:
        chip, chip_params = "all", {}
    filt = {k: request.args.get(k, "") for k in ("severity", "from", "to")}
    page = max(request.args.get("page", 0, type=int), 0)

    error = None
    if filt["from"] and filt["to"] and filt["from"] > filt["to"]:
        error = "시작일이 종료일보다 늦습니다."
    data, summary = {"content": [], "totalElements": 0}, None
    if error is None:
        try:
            cond = alerts.parse_search({**filt, **chip_params})
            with db.transaction() as conn:
                data = alerts.search(conn, cond, page, ALERT_PAGE_SIZE)
                summary = alerts.summary(conn, cond)
        except ApiError as e:
            error = e.message

    def link(**changes):
        params = {"chip": chip, **filt, "page": page, **changes}
        params = {k: v for k, v in params.items() if v not in ("", None, 0, "all")}
        return url_for("views.alerts_page") + ("?" + urlencode(params) if params else "")

    total_pages = max(1, -(-data["totalElements"] // ALERT_PAGE_SIZE))
    return render_template(
        "alerts.html", menu="alerts", chips=CHIPS, chip=chip, filt=filt, page=page, total_pages=total_pages,
        data=data, summary=summary, error=error, severities=SEVERITIES, link=link,
        page_size=ALERT_PAGE_SIZE, here=request.full_path.rstrip("?"),
    )


@bp.post("/alerts/<int:alert_id>/status")
def alert_status(alert_id):
    try:
        with db.transaction() as conn:
            alerts.change_status(conn, alert_id, request.form.get("status"))
    except ApiError as e:
        flash(e.message, "error")
    return redirect(_back(url_for("views.alerts_page")))


@bp.post("/alerts/<int:alert_id>/false-positive")
def alert_false_positive(alert_id):
    try:
        with db.transaction() as conn:
            alerts.set_false_positive(conn, alert_id, request.form.get("falsePositive") == "true",
                                      request.form.get("comment") or None)
    except ApiError as e:
        flash(e.message, "error")
    return redirect(_back(url_for("views.alerts_page")))


def _back(default):
    """처리 후 돌아갈 화면. 같은 사이트 안의 경로만 허용 (외부 주소로 이동 방지)."""
    nxt = request.form.get("next", "")
    parts = urlsplit(nxt)
    if nxt.startswith("/") and not nxt.startswith("//") and not parts.scheme and not parts.netloc \
            and "\\" not in nxt:
        return nxt
    return default
