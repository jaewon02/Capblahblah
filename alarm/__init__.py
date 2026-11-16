"""경보기 SIEM — 5. 보안 위협 탐지 및 경보 관리 (Flask API + React 화면)."""
import logging
import os
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory
from flask.json.provider import DefaultJSONProvider

from . import db
from .common import iso
from .config import Config
from .detect import DetectionEngine, DetectionScheduler

# React 빌드 결과 (cd frontend; npm run build)
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

_NO_BUILD_PAGE = """<!doctype html><meta charset="utf-8"><title>경보기 SIEM</title>
<body style="font-family:sans-serif;padding:32px;line-height:1.6">
<h1>화면 빌드가 없습니다</h1>
<p>API 서버는 실행 중입니다. 화면은 둘 중 하나로 여십시오.</p>
<ul><li>개발: <code>cd frontend; npm install; npm run dev</code> → http://localhost:5173</li>
<li>배포: <code>cd frontend; npm run build</code> 후 이 주소를 새로 고침</li></ul></body>"""


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
    app = Flask(__name__, static_folder=None)
    app.json = JsonProvider(app)
    app.config.from_object(Config)
    if config:
        app.config.update(config)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    db.init(app.config)

    engine = DetectionEngine(app.config["DETECTION_BATCH_SIZE"], app.config["DETECTION_STARTUP_LOOKBACK_MIN"])
    app.extensions["detection_engine"] = engine

    from . import api
    app.register_blueprint(api.bp)
    if app.config["PROFILE"] == "dev":
        from . import dev
        app.register_blueprint(dev.bp)

    _register_frontend(app)

    @app.errorhandler(404)
    @app.errorhandler(405)
    def http_error(e):
        message = "요청한 주소를 찾을 수 없습니다." if e.code == 404 else "지원하지 않는 요청 방식입니다."
        return jsonify(message=message), e.code

    # 디버그 모드 자동 재시작(reloader)일 때는 실제 실행 프로세스에서만 탐지 스레드를 띄운다
    reloader_parent = app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true"
    if start_scheduler and app.config["DETECTION_ENABLED"] and not reloader_parent:
        scheduler = DetectionScheduler(engine, app.config["DETECTION_INTERVAL_SEC"])
        scheduler.start()
        app.extensions["detection_scheduler"] = scheduler
    return app


def _register_frontend(app):
    """React 빌드(frontend/dist)를 내보낸다. 파일이 없는 경로는 index.html (화면 이동은 React Router 가 처리)."""

    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def frontend(path):
        if path == "api" or path.startswith("api/"):
            abort(404)
        if not (FRONTEND_DIST / "index.html").is_file():
            return _NO_BUILD_PAGE, 503
        if path and (FRONTEND_DIST / path).is_file():
            return send_from_directory(FRONTEND_DIST, path)
        return send_from_directory(FRONTEND_DIST, "index.html")
