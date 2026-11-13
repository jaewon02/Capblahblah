"""경보기 SIEM — 5. 보안 위협 탐지 및 경보 관리 (Flask)."""
import logging
import os
from datetime import datetime

import psycopg
from flask import Flask, jsonify, render_template, request
from flask.json.provider import DefaultJSONProvider
from psycopg_pool import PoolTimeout
from werkzeug.exceptions import HTTPException

from . import db
from .common import KST, iso
from .config import Config
from .detect import DetectionEngine, DetectionScheduler

SEVERITY_LABELS = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
SEVERITY_CLASSES = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info"}
ALERT_STATUS = {
    "NEW": {"label": "미확인", "cls": "st-new", "next": "ACK", "nextLabel": "확인"},
    "ACK": {"label": "확인", "cls": "st-ack", "next": "RESOLVED", "nextLabel": "처리 완료"},
    "RESOLVED": {"label": "처리 완료", "cls": "st-done", "next": None, "nextLabel": None},
}


class JsonProvider(DefaultJSONProvider):
    """한글을 그대로, 키 순서를 유지하고, 시각은 ISO-8601(UTC)로 내보낸다."""
    ensure_ascii = False
    sort_keys = False

    @staticmethod
    def default(o):
        if isinstance(o, datetime):
            return iso(o)
        return DefaultJSONProvider.default(o)


def create_app(config=None, start_scheduler=True):
    app = Flask(__name__)
    app.json = JsonProvider(app)
    app.config.from_object(Config)
    if config:
        app.config.update(config)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    db.init(app.config)

    engine = DetectionEngine(app.config["DETECTION_BATCH_SIZE"], app.config["DETECTION_STARTUP_LOOKBACK_MIN"])
    app.extensions["detection_engine"] = engine

    from . import api, views
    app.register_blueprint(api.bp)
    app.register_blueprint(views.bp)
    if app.config["PROFILE"] == "dev":
        from . import dev
        app.register_blueprint(dev.bp)

    _register_template_helpers(app)

    @app.errorhandler(404)
    @app.errorhandler(405)
    def http_error(e):
        message = "요청한 주소를 찾을 수 없습니다." if e.code == 404 else "지원하지 않는 요청 방식입니다."
        if request.path.startswith("/api/"):
            return jsonify(message=message), e.code
        return render_template("error.html", menu=None, title="페이지 오류", message=message), e.code

    # 화면 처리 중 오류: 메뉴가 있는 오류 화면을 보여 줘서 다른 화면으로 이동할 수 있게 한다
    # (API 오류는 api.py 에서 {"message"} 로 응답)
    @app.errorhandler(Exception)
    def page_error(e):
        if isinstance(e, HTTPException):
            return e
        if isinstance(e, (PoolTimeout, psycopg.OperationalError)):
            app.logger.error("DB 연결 실패: %s", e)
            return render_template(
                "error.html", menu=_menu_of(request.path), title="DB 연결 실패",
                message="데이터베이스에 연결할 수 없습니다.",
                hint="PostgreSQL이 실행 중인지, 환경변수 DB_PASSWORD(siem 계정 비밀번호)를 넣고 서버를 실행했는지 확인하십시오.",
            ), 503
        app.logger.exception("화면 처리 중 오류")
        return render_template("error.html", menu=_menu_of(request.path), title="서버 오류",
                               message="처리 중 오류가 발생했습니다. 잠시 후 다시 시도하십시오."), 500

    # 디버그 모드 자동 재시작(reloader)일 때는 실제 실행 프로세스에서만 탐지 스레드를 띄운다
    reloader_parent = app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true"
    if start_scheduler and app.config["DETECTION_ENABLED"] and not reloader_parent:
        scheduler = DetectionScheduler(engine, app.config["DETECTION_INTERVAL_SEC"])
        scheduler.start()
        app.extensions["detection_scheduler"] = scheduler
    return app


def _register_template_helpers(app):

    @app.template_filter("severity_label")
    def severity_label(s):
        return SEVERITY_LABELS.get(s, s)

    @app.template_filter("severity_class")
    def severity_class(s):
        return SEVERITY_CLASSES.get(s, "info")

    @app.template_filter("kst_time")
    def kst_time(value):
        """ISO 문자열 → KST "11-23 14:31:02" (오늘이면 시각만)."""
        if not value:
            return "-"
        try:
            t = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(KST)
        except ValueError:
            return value
        if t.date() == datetime.now(KST).date():
            return t.strftime("%H:%M:%S")
        return t.strftime("%m-%d %H:%M:%S")

    @app.context_processor
    def globals_():
        return {"alert_status": ALERT_STATUS}


def _menu_of(path):
    """오류 화면에서도 현재 메뉴를 표시하기 위한 메뉴 키 (/rules?... → rules)."""
    return path.strip("/").split("/")[0] or None

