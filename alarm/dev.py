"""개발 전용 API (APP_PROFILE=dev 일 때만 등록).

파싱 · 정규화 엔진(WBS 3.5)이 완성되기 전에 탐지 · 경보를 시험하기 위해
collect_target · raw_log · normalized_event 에 테스트 데이터를 명세서 컬럼 그대로 넣는다.
"""
import hashlib
from datetime import timedelta

from flask import Blueprint, current_app, jsonify

from . import db
from .api import handle_api_error, handle_unexpected
from .common import KST, ApiError, now_utc

bp = Blueprint("dev", __name__, url_prefix="/api/dev")
bp.register_error_handler(ApiError, handle_api_error)
bp.register_error_handler(Exception, handle_unexpected)

# 테스트용 수집 대상: 이름 → (IP, 로그 유형)
TARGETS = {
    "bastion": ("10.0.0.5", "AUTH"),
    "db-01": ("10.0.0.21", "SYSTEM"),
    "web-01": ("10.0.0.31", "WEB"),
}

SCENARIOS = ("ssh-bruteforce", "sudo-root", "offhours-login", "user-created", "web-admin-scan")


@bp.post("/simulate/<scenario>")
def simulate(scenario):
    """시나리오: ssh-bruteforce | sudo-root | offhours-login | user-created | web-admin-scan

    예) POST /api/dev/simulate/ssh-bruteforce
    """
    if scenario not in SCENARIOS:
        raise ApiError.bad_request(f"알 수 없는 시나리오: {scenario}")
    now = now_utc()
    with db.transaction() as conn:
        if scenario == "ssh-bruteforce":
            for i in range(15):
                user = "admin" if i % 3 == 0 else "root"
                _save(conn, now - timedelta(seconds=15 - i), "bastion", "AUTH", "ssh_auth_failed",
                      "203.0.113.47", user, None,
                      f"bastion sshd[{2200 + i}]: Failed password for {user} from 203.0.113.47 "
                      f"port {52200 + i} ssh2")
            count = 15
        elif scenario == "sudo-root":
            _save(conn, now, "db-01", "AUTH", "sudo_exec", "10.0.0.21", "deploy",
                  {"USER": "root", "COMMAND": "/bin/bash"},
                  "db-01 sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
            count = 1
        elif scenario == "offhours-login":
            t = now.astimezone(KST).replace(hour=2, minute=13)
            _save(conn, t, "bastion", "AUTH", "ssh_login_success", "198.51.100.12", "kim", None,
                  "bastion sshd[811]: Accepted publickey for kim from 198.51.100.12 port 40022 ssh2")
            count = 1
        elif scenario == "user-created":
            _save(conn, now, "db-01", "SYSTEM", "user_created", None, "deploy", {"new_user": "backup2"},
                  "db-01 useradd[3012]: new user: name=backup2, UID=1005, GID=1005")
            count = 1
        else:  # web-admin-scan
            for i in range(25):
                _save(conn, now - timedelta(seconds=25 - i), "web-01", "WEB", "http_403", "198.51.100.230", None,
                      {"path": "/admin/login.php", "status": 403},
                      '198.51.100.230 - - "GET /admin/login.php HTTP/1.1" 403 162')
            count = 25
    return jsonify(scenario=scenario, inserted=count)


@bp.post("/detect")
def detect_now():
    """다음 주기(10초)를 기다리지 않고 탐지 엔진 즉시 실행."""
    return jsonify(current_app.extensions["detection_engine"].run_all())


def _save(conn, t, host, log_type, event_type, src_ip, user, extra, body):
    target_id = _target(conn, host)
    raw_message = f"{t.astimezone(KST):%b %d %H:%M:%S} {body}"

    # raw_log: 파티션 키(received_at) 포함 PK. 같은 트랜잭션에서 normalized_event 와 함께 INSERT
    raw = conn.execute(
        """
        INSERT INTO raw_log (received_at, target_id, log_type_code, sender_ip, raw_message, dedup_hash, parse_status)
        VALUES (%s, %s, %s, %s::inet, %s, %s, 'SUCCESS')
        RETURNING raw_log_id, received_at
        """,
        (t, target_id, log_type, TARGETS[host][0], raw_message,
         hashlib.sha256(raw_message.encode("utf-8")).hexdigest())).fetchone()

    normalized = {
        "event_time": t.isoformat(),
        "log_type": log_type,
        "event_type": event_type,
        "source_ip": src_ip,
        "user_account": user,
        "host_name": host,
        "extra": extra,
    }
    conn.execute(
        """
        INSERT INTO normalized_event (event_time, raw_log_id, raw_received_at, target_id, log_type_code,
                                      event_type_code, source_ip, user_account, host_name, extra, normalized_json)
        VALUES (%s, %s, %s, %s, %s, %s, %s::inet, %s, %s, %s, %s)
        """,
        (t, raw["raw_log_id"], raw["received_at"], target_id, log_type, event_type, src_ip, user, host,
         db.jsonb(extra), db.jsonb(normalized)))


def _target(conn, name):
    """테스트용 수집 대상 조회, 없으면 생성."""
    row = conn.execute("SELECT target_id FROM collect_target WHERE name = %s AND deleted_at IS NULL",
                       (name,)).fetchone()
    if row:
        return row["target_id"]
    ip, log_type = TARGETS[name]
    return conn.execute(
        """
        INSERT INTO collect_target (name, ip_address, description, log_type_code, collect_method,
                                    syslog_protocol, syslog_port)
        VALUES (%s, %s::inet, '개발용 테스트 대상', %s, 'SYSLOG', 'UDP', 514)
        RETURNING target_id
        """, (name, ip, log_type)).fetchone()["target_id"]
