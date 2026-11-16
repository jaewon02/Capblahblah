"""경보기 SIEM 더미 데이터 생성기 — 기능정의서 238개 기능을 모두 시험할 수 있는 14일치 데이터.

실행 전제: schema.sql · data.sql 만 적용된 빈 DB (이벤트 · 경보가 0건)
실행: (저장소 최상위에서)
    $env:DB_PASSWORD = '비밀번호'; .venv\\Scripts\\python db\\dummy\\generate_dummy.py
필요 패키지: requirements.txt + bcrypt (비밀번호 해시)

위협 이벤트 · 근거 로그 연결 · 경보는 직접 만들지 않고 실제 탐지 엔진(alarm.detect)을 돌려 만든다.
같은 시드(SEED)면 언제 실행해도 같은 데이터가 나온다.
"""
import hashlib
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import bcrypt
import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

KST = ZoneInfo("Asia/Seoul")
UTC = timezone.utc
SEED = 20261116
END = datetime(2026, 11, 16, 16, 0, 0, tzinfo=KST)          # 기준 시각 (데이터의 '현재')
DAYS = 14
START = (END - timedelta(days=DAYS - 1)).replace(hour=0, minute=0, second=0, microsecond=0)  # 11-03 00:00 KST
TEST_PASSWORD = "Siem!Test2026"                              # 모든 더미 관리자 계정 공통 (테스트 전용)
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

rnd = random.Random(SEED)


def at(d, h, m=0, s=0):
    """START 기준 d일째 h:m:s (KST) → UTC datetime"""
    return (START + timedelta(days=d, hours=h, minutes=m, seconds=s)).astimezone(UTC)


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def syslog_ts(t):
    k = t.astimezone(KST)
    return f"{MONTHS[k.month - 1]} {k.day:2d} {k:%H:%M:%S}"


def clf_ts(t):
    k = t.astimezone(KST)
    return f"{k.day:02d}/{MONTHS[k.month - 1]}/{k.year}:{k:%H:%M:%S} +0900"


# ═══════════════════════════════════ 고정 데이터 ═══════════════════════════════════

USERS = [  # login_id, 표시 이름, 역할, 연속 실패, 잠김, 사용 여부
    ("admin", "관리자", "ADMIN", 0, False, True),
    ("analyst01", "보안분석가1", "ANALYST", 0, False, True),
    ("analyst02", "보안분석가2", "ANALYST", 0, False, True),
    ("viewer01", "조회전용", "VIEWER", 0, False, True),
    ("analyst03", "보안분석가3(잠김)", "ANALYST", 5, True, True),
    ("olduser", "퇴직자(비활성)", "VIEWER", 0, False, False),
]
OFFICE_IP = {"admin": "10.0.1.10", "analyst01": "10.0.1.11", "analyst02": "10.0.1.12",
             "viewer01": "10.0.1.13", "analyst03": "10.0.1.14", "olduser": "10.0.1.19"}

TARGETS = [  # name, ip, 설명, 로그 유형, 수집 방식, 프로토콜, 포트, api_url, 인증정보 참조, cron, 사용, 삭제(일)
    ("bastion", "10.0.0.5", "SSH 접속 관문 서버", "AUTH", "SYSLOG", "UDP", 514, None, None, None, True, None),
    ("db-01", "10.0.0.21", "운영 DB 서버 (PostgreSQL)", "SYSTEM", "SYSLOG", "TCP", 514, None, None, None, True, None),
    ("was-02", "10.0.0.32", "WAS 서버 2호기", "SYSTEM", "SYSLOG", "TLS", 6514, None, None, None, True, None),
    ("web-01", "10.0.0.31", "대외 웹 서버 (nginx)", "WEB", "SYSLOG", "UDP", 514, None, None, None, True, None),
    ("fw-01", "10.0.0.1", "경계 방화벽", "NETWORK", "SYSLOG", "UDP", 514, None, None, None, True, None),
    ("api-gw", "10.0.0.40", "API 게이트웨이 (REST 배치 수집)", "WEB", "REST_API", None, None,
     "https://api-gw.internal/v1/access-logs", "vault:siem/api-gw-token", "0 2 * * *", True, None),
    ("legacy-ftp", "10.0.0.60", "구형 FTP 서버 (로그 파일 업로드)", "AUTH", "FILE_UPLOAD", None, None, None, None, None, True, None),
    ("test-vm", "10.0.0.99", "테스트 VM (수집 중지)", "SYSTEM", "SYSLOG", "UDP", 514, None, None, None, False, None),
    ("old-mail", "10.0.0.70", "구 메일 서버 (폐기)", "SYSTEM", "SYSLOG", "UDP", 514, None, None, None, False, 6),
]

EVENT_TYPE_UPDATES = {  # 기존 9개: 공격 유형 · ATT&CK · 기본 등급
    "ssh_auth_failed": ("SSH 반복 인증 시도", "T1110", "LOW"),
    "ssh_login_success": (None, None, "INFO"),
    "sudo_exec": (None, None, "INFO"),
    "user_created": ("계정 조작", "T1136", "MEDIUM"),
    "user_deleted": ("계정 조작", "T1531", "MEDIUM"),
    "usermod": ("계정 조작", "T1098", "MEDIUM"),
    "auditd_stopped": ("감사 로그 무력화", "T1562", "HIGH"),
    "audit_rule_changed": ("감사 로그 무력화", "T1562", "HIGH"),
    "http_403": ("웹 관리자 페이지 탐색", "T1595", "LOW"),
}
EVENT_TYPE_NEW = [  # code, name, log type, attack, mitre, severity
    ("ssh_logout", "SSH 로그아웃", "AUTH", None, None, "INFO"),
    ("service_restart", "서비스 재시작", "SYSTEM", None, None, "INFO"),
    ("http_access", "HTTP 정상 접근", "WEB", None, None, "INFO"),
    ("http_404", "HTTP 404 응답", "WEB", "웹 경로 탐색", "T1595", "LOW"),
    ("fw_allow", "방화벽 허용", "NETWORK", None, None, "INFO"),
    ("fw_deny", "방화벽 차단", "NETWORK", "포트 스캔", "T1046", "LOW"),
]

PARSE_RULES = [  # name, category, log type, match, extract, mapping, event type, time format, priority, active
    ("sshd Failed password", "SSH_AUTH", "AUTH", r"sshd\[\d+\]: Failed password",
     r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)",
     {"user": "user_account", "src_ip": "source_ip"}, "ssh_auth_failed", "%b %d %H:%M:%S", 10, True),
    ("sshd Accepted", "SSH_AUTH", "AUTH", r"sshd\[\d+\]: Accepted",
     r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)",
     {"user": "user_account", "src_ip": "source_ip"}, "ssh_login_success", "%b %d %H:%M:%S", 10, True),
    ("sshd session closed", "SSH_AUTH", "AUTH", r"session closed for user",
     r"session closed for user (?P<user>\S+)", {"user": "user_account"}, "ssh_logout", "%b %d %H:%M:%S", 20, True),
    ("sudo COMMAND", "SYSTEM_EVENT", "AUTH", r"sudo: .* COMMAND=",
     r"sudo: (?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=(?P<USER>\S+) ; COMMAND=(?P<COMMAND>.+)$",
     {"user": "user_account", "USER": "extra.USER", "COMMAND": "extra.COMMAND"}, "sudo_exec", "%b %d %H:%M:%S", 10, True),
    ("useradd/userdel/usermod", "ACCOUNT_CHANGE", "SYSTEM", r"(useradd|userdel|usermod)\[\d+\]",
     r"(?P<cmd>useradd|userdel|usermod)\[\d+\]: (?P<detail>.+)$",
     {"cmd": "event_type_code", "detail": "extra.detail"}, None, "%b %d %H:%M:%S", 10, True),
    ("auditd 상태 변경", "SYSTEM_EVENT", "SYSTEM", r"(Security Auditing Service|auditctl)",
     r"(?P<msg>Stopped Security Auditing Service|rule deleted.*)$",
     {"msg": "extra.message"}, None, "%b %d %H:%M:%S", 10, True),
    ("systemd 재시작", "SYSTEM_EVENT", "SYSTEM", r"systemd\[1\]: Restarted",
     r"Restarted (?P<service>.+)\.$", {"service": "extra.service"}, "service_restart", "%b %d %H:%M:%S", 50, True),
    ("iptables FW", "NETWORK_FW", "NETWORK", r"\[FW-(ACCEPT|DROP)\]",
     r"\[FW-(?P<action>ACCEPT|DROP)\] .*SRC=(?P<src_ip>\S+) DST=(?P<dst_ip>\S+) .*DPT=(?P<dst_port>\d+)",
     {"src_ip": "source_ip", "dst_ip": "dest_ip", "dst_port": "dest_port", "action": "event_type_code"},
     None, "%b %d %H:%M:%S", 10, True),
    ("nginx access", "WEB_ACCESS", "WEB", r"nginx: \S+ - - \[",
     r'nginx: (?P<src_ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]+" (?P<status>\d{3})',
     {"src_ip": "source_ip", "path": "extra.path", "status": "extra.status", "method": "extra.method"},
     None, "%d/%b/%Y:%H:%M:%S %z", 10, True),
    ("api-gw JSON", "WEB_ACCESS", "WEB", r'^\{"ts"',
     r'"client":"(?P<src_ip>[^"]+)".*"path":"(?P<path>[^"]+)".*"status":(?P<status>\d+)',
     {"src_ip": "source_ip", "path": "extra.path", "status": "extra.status"}, None, "ISO8601", 10, True),
    ("apache combined (구버전)", "WEB_ACCESS", "WEB", r"httpd\[\d+\]",
     r'(?P<src_ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)',
     {"src_ip": "source_ip", "path": "extra.path"}, None, "%d/%b/%Y:%H:%M:%S %z", 90, False),
]
RULE_OF_EVENT = {  # 이벤트 유형 → 적용 파싱 규칙 이름
    "ssh_auth_failed": "sshd Failed password", "ssh_login_success": "sshd Accepted", "ssh_logout": "sshd session closed",
    "sudo_exec": "sudo COMMAND", "user_created": "useradd/userdel/usermod", "user_deleted": "useradd/userdel/usermod",
    "usermod": "useradd/userdel/usermod", "auditd_stopped": "auditd 상태 변경", "audit_rule_changed": "auditd 상태 변경",
    "service_restart": "systemd 재시작", "fw_allow": "iptables FW", "fw_deny": "iptables FW",
    "http_access": "nginx access", "http_403": "nginx access", "http_404": "nginx access",
}

STAFF = {"ops": "10.0.1.21", "kim": "10.0.1.22", "lee": "10.0.1.23", "park": "10.0.1.24", "deploy": "10.0.1.25"}
WEB_PATHS = ["/", "/index.html", "/products", "/products/1024", "/cart", "/login", "/search?q=siem", "/about",
             "/static/app.js", "/static/style.css", "/api/v1/items", "/news/2026/11"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6)",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1)", "curl/8.9.1"]
PUBLIC_CLIENTS = [f"198.51.100.{i}" for i in range(20, 60)] + [f"203.0.113.{i}" for i in range(120, 150)]


# ═══════════════════════════════════ 이벤트 생성 ═══════════════════════════════════

class Gen:
    def __init__(self):
        self.recs = []   # 원본 로그 1건 = dict

    def add(self, target, t, etype, raw, src=None, dst=None, dport=None, user=None, extra=None,
            parse="OK", fail=None, recv=None):
        self.recs.append({
            "target": target, "event_time": t, "received_at": recv or t + timedelta(milliseconds=rnd.randint(50, 2500)),
            "event_type": etype, "raw": raw, "src": src, "dst": dst, "dport": dport, "user": user,
            "extra": extra, "parse": parse, "fail": fail,
        })

    # ── 로그 한 줄 만들기 ──
    def ssh_fail(self, t, host, user, ip, invalid=False, target="bastion", recv=None):
        port = rnd.randint(40000, 65000)
        raw = (f"{syslog_ts(t)} {host} sshd[{rnd.randint(1000, 9999)}]: Failed password for "
               f"{'invalid user ' if invalid else ''}{user} from {ip} port {port} ssh2")
        self.add(target, t, "ssh_auth_failed", raw, src=ip, dst=self.ip(target), dport=22, user=user, recv=recv)

    def ssh_ok(self, t, host, user, ip, method="publickey", target="bastion", recv=None):
        raw = (f"{syslog_ts(t)} {host} sshd[{rnd.randint(1000, 9999)}]: Accepted {method} for {user} "
               f"from {ip} port {rnd.randint(40000, 65000)} ssh2")
        self.add(target, t, "ssh_login_success", raw, src=ip, dst=self.ip(target), dport=22, user=user,
                 extra={"method": method}, recv=recv)

    def ssh_logout(self, t, host, user, target="bastion"):
        raw = f"{syslog_ts(t)} {host} sshd[{rnd.randint(1000, 9999)}]: pam_unix(sshd:session): session closed for user {user}"
        self.add(target, t, "ssh_logout", raw, user=user)

    def sudo(self, t, host, user, runas, cmd):
        raw = (f"{syslog_ts(t)} {host} sudo: {user} : TTY=pts/{rnd.randint(0, 4)} ; PWD=/home/{user} ; "
               f"USER={runas} ; COMMAND={cmd}")
        self.add(host, t, "sudo_exec", raw, user=user, extra={"USER": runas, "COMMAND": cmd})

    def account(self, t, host, etype, actor, detail):
        cmd = {"user_created": "useradd", "user_deleted": "userdel", "usermod": "usermod"}[etype]
        raw = f"{syslog_ts(t)} {host} {cmd}[{rnd.randint(1000, 9999)}]: {detail}"
        self.add(host, t, etype, raw, user=actor, extra={"detail": detail})

    def audit(self, t, host, etype):
        msg = ("Stopped Security Auditing Service." if etype == "auditd_stopped"
               else "rule deleted: -w /etc/passwd -p wa -k identity")
        prog = "systemd[1]" if etype == "auditd_stopped" else f"auditctl[{rnd.randint(1000, 9999)}]"
        self.add(host, t, etype, f"{syslog_ts(t)} {host} {prog}: {msg}", user="root", extra={"message": msg})

    def restart(self, t, host, service):
        self.add(host, t, "service_restart", f"{syslog_ts(t)} {host} systemd[1]: Restarted {service}.",
                 extra={"service": service})

    def web(self, t, ip, path, status, method="GET"):
        etype = {403: "http_403", 404: "http_404"}.get(status, "http_access")
        raw = (f'{syslog_ts(t)} web-01 nginx: {ip} - - [{clf_ts(t)}] "{method} {path} HTTP/1.1" {status} '
               f'{rnd.randint(200, 9000)} "-" "{rnd.choice(UAS)}"')
        self.add("web-01", t, etype, raw, src=ip, dst="10.0.0.31", dport=443,
                 extra={"path": path, "status": status, "method": method})

    def api(self, t, ip, path, status, recv):
        raw = ('{"ts":"%s","client":"%s","method":"GET","path":"%s","status":%d,"latency_ms":%d}'
               % (t.astimezone(KST).isoformat(timespec="seconds"), ip, path, status, rnd.randint(5, 900)))
        etype = {403: "http_403", 404: "http_404"}.get(status, "http_access")
        self.add("api-gw", t, etype, raw, src=ip, dst="10.0.0.40", dport=443,
                 extra={"path": path, "status": status, "method": "GET"}, recv=recv)

    def fw(self, t, action, src, dst, dport):
        etype = "fw_allow" if action == "ACCEPT" else "fw_deny"
        raw = (f"{syslog_ts(t)} fw-01 kernel: [FW-{action}] IN=eth0 OUT=eth1 SRC={src} DST={dst} LEN=60 "
               f"PROTO=TCP SPT={rnd.randint(1024, 65000)} DPT={dport}")
        self.add("fw-01", t, etype, raw, src=src, dst=dst, dport=dport, extra={"action": action})

    def junk(self, t, target, reason):
        """파싱 실패 로그 (No 79–80)"""
        host = target
        raw = {
            "NO_MATCHING_RULE": f"{syslog_ts(t)} {host} kernel: [{rnd.randint(1000, 99999)}.{rnd.randint(100, 999)}] "
                                f"usb 1-1: new high-speed USB device number {rnd.randint(2, 9)} using xhci_hcd",
            "TIME_FORMAT": f"2026/13/{rnd.randint(40, 99)} 25:61:00 {host} sshd[{rnd.randint(1000, 9999)}]: "
                           f"Accepted publickey for ops from 10.0.1.21 port 51000 ssh2",
            "MISSING_FIELD": f"{syslog_ts(t)} {host} sshd[{rnd.randint(1000, 9999)}]: Failed password for",
        }[reason]
        self.add(target, t, None, raw, parse="FAIL", fail=reason)

    @staticmethod
    def ip(target):
        return next(t[1] for t in TARGETS if t[0] == target)


def build_events():
    g = Gen()
    end_utc = END.astimezone(UTC)

    def ok(t):
        return t <= end_utc - timedelta(seconds=30)

    for d in range(DAYS):
        weekend = (START + timedelta(days=d)).weekday() >= 5

        # ── 평상시: 직원 SSH 로그인 · 로그아웃 (09–18시) ──
        for user, ip in STAFF.items():
            if weekend and user != "ops":
                continue
            t = at(d, rnd.randint(9, 10), rnd.randint(0, 59), rnd.randint(0, 59))
            if not ok(t):
                continue
            if rnd.random() < 0.25:  # 비밀번호 오타 1~2번 (임계값 미달)
                for _ in range(rnd.randint(1, 2)):
                    g.ssh_fail(t - timedelta(seconds=rnd.randint(5, 40)), "bastion", user, ip)
            g.ssh_ok(t, "bastion", user, ip)
            out = at(d, rnd.randint(17, 17), rnd.randint(0, 50))
            if ok(out):
                g.ssh_logout(out, "bastion", user)

        # ── 평상시: 운영 작업 sudo (조건 불일치 → 탐지 안 됨) · 서비스 재시작 ──
        for _ in range(rnd.randint(3, 6)):
            t = at(d, rnd.randint(9, 17), rnd.randint(0, 59), rnd.randint(0, 59))
            if ok(t):
                host = rnd.choice(["db-01", "was-02"])
                cmd = rnd.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u app", "/usr/bin/tail -f /var/log/app.log",
                                  "/usr/bin/systemctl status postgresql", "/usr/bin/apt list --upgradable"])
                g.sudo(t, host, rnd.choice(["deploy", "ops", "park"]), "root", cmd)
        for host, svc in [("db-01", "PostgreSQL database server"), ("was-02", "Application Server (tomcat)")]:
            if rnd.random() < 0.4:
                t = at(d, rnd.randint(2, 4), rnd.randint(0, 59))
                if ok(t):
                    g.restart(t, host, svc)

        # ── 평상시: 웹 접근 · 404 · 403 소량 ──
        for _ in range(rnd.randint(70, 110)):
            h = rnd.choices(range(24), weights=[1, 1, 1, 1, 1, 2, 3, 5, 8, 9, 9, 9, 8, 9, 9, 9, 8, 7, 6, 6, 5, 4, 3, 2])[0]
            t = at(d, h, rnd.randint(0, 59), rnd.randint(0, 59))
            if not ok(t):
                continue
            r = rnd.random()
            status, path = (404, rnd.choice(["/wp-login.php", "/.env", "/old/page", "/favicon.ico"])) if r < 0.06 else \
                           (403, "/admin") if r < 0.08 else (200, rnd.choice(WEB_PATHS))
            g.web(t, rnd.choice(PUBLIC_CLIENTS), path, status)

        # ── 평상시: 방화벽 허용 · 차단 ──
        for _ in range(rnd.randint(30, 45)):
            t = at(d, rnd.randint(0, 23), rnd.randint(0, 59), rnd.randint(0, 59))
            if ok(t):
                g.fw(t, "ACCEPT", rnd.choice(PUBLIC_CLIENTS), "10.0.0.31", rnd.choice([80, 443]))
        for _ in range(rnd.randint(8, 18)):
            t = at(d, rnd.randint(0, 23), rnd.randint(0, 59), rnd.randint(0, 59))
            if ok(t):
                g.fw(t, "DROP", rnd.choice(PUBLIC_CLIENTS), rnd.choice(["10.0.0.21", "10.0.0.5"]), rnd.choice([22, 3389, 5432, 23]))

        # ── 파싱 실패 로그 (하루 2~4건) ──
        for _ in range(rnd.randint(2, 4)):
            t = at(d, rnd.randint(0, 23), rnd.randint(0, 59))
            if ok(t):
                g.junk(t, rnd.choice(["bastion", "db-01", "was-02"]),
                       rnd.choice(["NO_MATCHING_RULE", "NO_MATCHING_RULE", "TIME_FORMAT", "MISSING_FIELD"]))

        # ── REST API 배치(api-gw): 전날 접근 로그를 매일 02:00에 수집 ──
        if d >= 1 and d not in API_FAIL_DAYS:
            recv = at(d, 2, 0, 5)
            n = rnd.randint(25, 40) if d not in API_PARTIAL_DAYS else 12
            for _ in range(n):
                t = at(d - 1, rnd.randint(8, 22), rnd.randint(0, 59), rnd.randint(0, 59))
                status = rnd.choices([200, 404, 403, 500], weights=[85, 8, 4, 3])[0]
                g.api(t, rnd.choice(PUBLIC_CLIENTS), rnd.choice(["/v1/orders", "/v1/items", "/v1/users/me", "/v1/admin/config"]),
                      status, recv + timedelta(milliseconds=rnd.randint(0, 900)))

    # ═════════════ 공격 · 이상행위 시나리오 (탐지 규칙별) ═════════════
    # [규칙1] SSH 반복 인증 실패 (> 10회 / 5분, 출발지 IP)
    def brute(d, h, m, ip, n, seconds, users=("root", "admin", "test", "oracle", "ubuntu")):
        base = at(d, h, m)
        for i in range(n):
            u = rnd.choice(users)
            g.ssh_fail(base + timedelta(seconds=seconds * i / n + rnd.random()), "bastion", u, ip, invalid=u in ("test", "oracle"))

    brute(2, 3, 12, "203.0.113.47", 60, 170)           # 새벽 무차별 대입
    brute(4, 11, 0, "198.51.100.12", 8, 200)            # 임계값 미달 (탐지 안 됨)
    brute(6, 14, 40, "198.51.100.77", 25, 110)
    brute(9, 22, 5, "192.0.2.10", 120, 900)             # 15분 지속 → 중복 억제 10분 뒤 재탐지
    brute(11, 10, 0, "10.0.0.50", 40, 120, users=("svc-scanner",))  # 내부 취약점 스캐너 → 예외 조건으로 제외
    brute(13, 15, 30, "203.0.113.47", 318, 290)         # 오늘: 같은 IP 재공격 (목업 318회)

    # [규칙2] 운영 시간 외 로그인 (09–18시 외, 사용자 계정)
    g.ssh_ok(at(1, 2, 13, 41), "bastion", "kim", "198.51.100.12", method="password")
    g.ssh_ok(at(5, 23, 40, 2), "bastion", "ops", "10.0.1.21")          # 정기 점검 → 오탐 처리
    g.ssh_ok(at(8, 6, 30, 15), "bastion", "deploy", "10.0.1.25")
    g.ssh_ok(at(12, 1, 5, 9), "bastion", "kim", "203.0.113.200", method="password")

    # [규칙3] sudo root 셸 + [규칙4] 계정 생성 · 삭제 · 권한 변경
    g.sudo(at(3, 14, 12, 45), "db-01", "deploy", "root", "/bin/bash")
    g.account(at(3, 14, 15, 2), "db-01", "user_created", "root", "new user: name=backup2, UID=1005, GID=1005, home=/home/backup2, shell=/bin/bash")
    g.sudo(at(7, 11, 20, 10), "was-02", "park", "root", "/bin/sh")
    g.account(at(7, 11, 25, 33), "was-02", "usermod", "root", "add 'park' to group 'wheel'")
    g.account(at(10, 9, 30, 0), "db-01", "user_deleted", "root", "delete user 'temp01'")          # 계획된 정리 → 오탐
    g.sudo(at(12, 16, 45, 20), "db-01", "deploy", "root", "/bin/bash")
    g.account(at(13, 13, 40, 11), "db-01", "user_created", "root", "new user: name=svc_tmp, UID=1006, GID=1006, home=/home/svc_tmp, shell=/bin/bash")

    # [규칙5 · 비활성] 감사 로그 무력화 → 규칙이 꺼져 있어 탐지되지 않아야 정상
    g.audit(at(7, 11, 30, 5), "was-02", "auditd_stopped")
    g.audit(at(10, 9, 32, 40), "db-01", "audit_rule_changed")

    # [규칙6] 웹 관리자 경로 403 반복 (> 20회 / 10분)
    def scan403(d, h, m, ip, n, seconds):
        for i in range(n):
            g.web(at(d, h, m) + timedelta(seconds=seconds * i / n + rnd.random()), ip,
                  rnd.choice(["/admin", "/admin/login.php", "/admin/config", "/administrator", "/admin/.git"]), 403)

    scan403(4, 21, 0, "198.51.100.230", 45, 400)
    scan403(9, 3, 30, "203.0.113.99", 25, 300)
    scan403(11, 15, 0, "198.51.100.9", 12, 500)          # 임계값 미달
    scan403(13, 14, 0, "198.51.100.230", 30, 420)

    # [규칙7 · 사용자 등록] 방화벽 포트 스캔 (> 30회 / 1분)
    for i in range(80):
        g.fw(at(9, 3, 20) + timedelta(seconds=55 * i / 80), "DROP", "203.0.113.99",
             rnd.choice(["10.0.0.5", "10.0.0.21", "10.0.0.31"]), rnd.choice([21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]))
    for i in range(20):  # 임계값 미달
        g.fw(at(12, 4, 0) + timedelta(seconds=50 * i / 20), "DROP", "198.51.100.66", "10.0.0.31", rnd.choice([22, 80, 8080]))

    # 업로드 파일(legacy-ftp)에 들어 있던 로그: 업로드 시각에 수집
    for d, upload_at in UPLOAD_OK.items():
        recv = at(d, *upload_at)
        for _ in range(rnd.randint(15, 25)):
            t = at(d - 1, rnd.randint(9, 16), rnd.randint(0, 59), rnd.randint(0, 59))  # 업무 시간 접속만
            user = rnd.choice(["ftpuser", "backup", "ops"])
            if rnd.random() < 0.3:
                g.ssh_fail(t, "legacy-ftp", user, rnd.choice(PUBLIC_CLIENTS), target="legacy-ftp",
                           recv=recv + timedelta(milliseconds=rnd.randint(0, 900)))
            else:
                g.ssh_ok(t, "legacy-ftp", user, rnd.choice(list(STAFF.values())), method="password", target="legacy-ftp",
                         recv=recv + timedelta(milliseconds=rnd.randint(0, 900)))

    # 파싱 실패 후 재시도로 성공한 로그 (parse_result attempt 1 FAIL → 2 SUCCESS)
    for r in rnd.sample([r for r in g.recs if r["parse"] == "OK" and r["target"] in ("db-01", "was-02")], 6):
        r["parse"] = "RETRY"
    # 방금 수집돼 아직 파싱 전인 로그 (PENDING)
    for i in range(5):
        t = END.astimezone(UTC) - timedelta(seconds=25 - i * 4)
        g.add("bastion", t, None, f"{syslog_ts(t)} bastion sshd[{rnd.randint(1000, 9999)}]: Accepted publickey for ops "
                                  f"from 10.0.1.21 port {rnd.randint(40000, 65000)} ssh2", parse="PENDING")

    g.recs.sort(key=lambda r: r["event_time"])
    return g.recs


API_FAIL_DAYS = {4, 10, 13}     # REST API 수집 실패 (HTTP 401)
API_PARTIAL_DAYS = {7}          # 응답 시간 초과로 일부만 수집
UPLOAD_OK = {2: (10, 5), 8: (15, 40)}   # legacy-ftp 업로드 성공 (일: 시각)
UPLOAD_FAIL_DAY = (11, 9, 10)            # 인코딩 감지 실패


# ═══════════════════════════════════ 메인 ═══════════════════════════════════

def main():
    conninfo = make_conninfo(
        host=os.environ.get("DB_HOST", "localhost"), port=os.environ.get("DB_PORT", "5432"),
        dbname=os.environ.get("DB_NAME", "siem"), user=os.environ.get("DB_USERNAME", "siem"),
        password=os.environ.get("DB_PASSWORD", ""))
    conn = psycopg.connect(conninfo, row_factory=dict_row, options="-c TimeZone=UTC")
    c = conn.execute

    if c("SELECT (SELECT count(*) FROM normalized_event) + (SELECT count(*) FROM alert) + "
         "(SELECT count(*) FROM admin_user) AS n").fetchone()["n"]:
        sys.exit("DB가 비어 있지 않습니다. schema.sql · data.sql 만 적용한 빈 DB에서 실행하십시오.")

    audits = []   # (시각, user, menu, action, table, id, before, after, summary, ip)

    def audit(t, user, menu, action, table, tid, before, after, summary):
        audits.append((t, uid.get(user), menu, action, table, None if tid is None else str(tid),
                       before, after, summary, OFFICE_IP.get(user)))

    # ── 1. 관리자 계정 ──
    uid = {}
    for login, name, role, fails, locked, active in USERS:
        h = bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt(10)).decode()
        created = at(-30, 9)
        row = c("""INSERT INTO admin_user (login_id, password_hash, display_name, role, failed_login_count, locked_until,
                                           password_changed_at, last_login_at, is_active, created_at, updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING user_id""",
                (login, h, name, role, fails, END.astimezone(UTC) + timedelta(minutes=12) if locked else None,
                 created, None, active, created, created)).fetchone()
        uid[login] = row["user_id"]
    c("UPDATE admin_user SET password_changed_at = %s WHERE login_id = 'analyst02'", (at(6, 10, 5),))
    audit(at(6, 10, 5), "analyst02", "비밀번호 변경", "PASSWORD_CHANGE", "admin_user", uid["analyst02"],
          None, None, "analyst02 비밀번호 변경")

    # ── 2. 로그인 이력 · 세션 ──
    logins, sessions = [], []
    for d in range(DAYS):
        if (START + timedelta(days=d)).weekday() >= 5:
            continue
        for user in ("admin", "analyst01", "analyst02", "viewer01"):
            if user == "viewer01" and d % 3:
                continue
            t_in = at(d, 8, rnd.randint(40, 59), rnd.randint(0, 59))
            if t_in > END.astimezone(UTC):
                continue
            if rnd.random() < 0.15:
                logins.append((uid[user], user, OFFICE_IP[user], "FAIL", "BAD_PASSWORD", t_in - timedelta(seconds=20)))
            logins.append((uid[user], user, OFFICE_IP[user], "SUCCESS", None, t_in))
            last = at(d, 17, rnd.randint(0, 50))
            today = d == DAYS - 1
            if today and user in ("admin", "analyst01"):
                sessions.append((user, t_in, END.astimezone(UTC) - timedelta(minutes=rnd.randint(1, 5)), None))
            elif rnd.random() < 0.2:   # 미사용 만료 (No 15–16)
                idle = at(d, 15, rnd.randint(0, 59))
                sessions.append((user, t_in, idle, None))
                logins.append((uid[user], user, OFFICE_IP[user], "EXPIRED", None, idle + timedelta(minutes=30)))
            elif last <= END.astimezone(UTC):
                sessions.append((user, t_in, last, last))
                logins.append((uid[user], user, OFFICE_IP[user], "LOGOUT", None, last))
    for d in (3, 8, 12):   # 외부에서 없는 계정 시도 (user_id NULL)
        for login in ("root", "test", "administrator"):
            logins.append((None, login, "198.51.100.200", "FAIL", "NO_USER", at(d, 2, 10, rnd.randint(0, 59))))
    lock_at = END.astimezone(UTC) - timedelta(minutes=3)   # analyst03: 5회 실패 → 잠김 (No 6–8)
    for i in range(5):
        logins.append((uid["analyst03"], "analyst03", OFFICE_IP["analyst03"], "FAIL", "BAD_PASSWORD", lock_at - timedelta(seconds=50 - i * 10)))
    logins.append((uid["analyst03"], "analyst03", OFFICE_IP["analyst03"], "LOCKED", "LOCKED", lock_at))
    audit(lock_at, None, "로그인", "LOCK", "admin_user", uid["analyst03"], {"failed_login_count": 4},
          {"failed_login_count": 5, "locked_minutes": 15}, "analyst03 연속 5회 로그인 실패로 15분간 로그인 제한")
    with conn.cursor() as cur:
        cur.executemany("""INSERT INTO login_history (user_id, input_login_id, client_ip, result, fail_reason, created_at)
                           VALUES (%s,%s,%s::inet,%s,%s,%s)""", logins)
        cur.executemany("""INSERT INTO admin_session (token_hash, user_id, client_ip, user_agent, created_at,
                                                      last_activity_at, expires_at, revoked_at)
                           VALUES (%s,%s,%s::inet,%s,%s,%s,%s,%s)""",
                        [(sha(f"{u}{t}{rnd.random()}"), uid[u], OFFICE_IP[u], UAS[0], t, last, last + timedelta(minutes=30), rev)
                         for u, t, last, rev in sessions])
    for u in ("admin", "analyst01", "analyst02", "viewer01"):
        c("""UPDATE admin_user SET last_login_at = (SELECT max(created_at) FROM login_history
                                                     WHERE user_id = %s AND result = 'SUCCESS') WHERE user_id = %s""", (uid[u], uid[u]))

    # ── 3. 수집 대상 ──
    tid = {}
    for name, ip, desc, lt, method, proto, port, url, cred, cron, active, deleted in TARGETS:
        created = at(-20, 10)
        row = c("""INSERT INTO collect_target (name, ip_address, description, log_type_code, collect_method, syslog_protocol,
                                               syslog_port, api_url, api_credential_ref, collect_cron, is_active,
                                               created_by, created_at, updated_at, deleted_at)
                   VALUES (%s,%s::inet,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING target_id""",
                (name, ip, desc, lt, method, proto, port, url, cred, cron, active, uid["admin"], created, created,
                 None if deleted is None else at(deleted, 10, 30))).fetchone()
        tid[name] = row["target_id"]
        audit(created, "admin", "로그 수집 관리", "CREATE", "collect_target", tid[name], None,
              {"name": name, "ip_address": ip, "log_type_code": lt, "collect_method": method}, f"수집 대상 등록: {name}")
    c("UPDATE collect_target SET updated_at = %s WHERE name = 'was-02'", (at(1, 14, 0),))
    audit(at(1, 14, 0), "analyst01", "로그 수집 관리", "UPDATE", "collect_target", tid["was-02"],
          {"syslog_protocol": "TCP", "syslog_port": 514}, {"syslog_protocol": "TLS", "syslog_port": 6514},
          "수집 대상 수정: was-02 (Syslog TCP 514 → TLS 6514)")
    c("UPDATE collect_target SET updated_at = %s WHERE name = 'test-vm'", (at(2, 9, 0),))
    audit(at(2, 9, 0), "admin", "로그 수집 관리", "UPDATE", "collect_target", tid["test-vm"],
          {"is_active": True}, {"is_active": False}, "수집 대상 수정: test-vm 수집 중지")
    audit(at(6, 10, 30), "admin", "로그 수집 관리", "DELETE", "collect_target", tid["old-mail"],
          {"name": "old-mail", "ip_address": "10.0.0.70"}, None, "수집 대상 삭제: old-mail (서버 폐기)")

    # ── 4. 이벤트 유형 · 파싱 규칙 ──
    for code, (attack, mitre, sev) in EVENT_TYPE_UPDATES.items():
        c("UPDATE event_type SET attack_type=%s, mitre_technique=%s, default_severity=%s WHERE event_type_code=%s",
          (attack, mitre, sev, code))
    for row in EVENT_TYPE_NEW:
        c("""INSERT INTO event_type (event_type_code, name, log_type_code, attack_type, mitre_technique, default_severity)
             VALUES (%s,%s,%s,%s,%s,%s)""", row)
    prid = {}
    for name, cat, lt, match, extract, mapping, et, tf, prio, active in PARSE_RULES:
        row = c("""INSERT INTO parse_rule (name, category, log_type_code, match_pattern, extract_pattern, field_mapping,
                                           event_type_code, time_format, priority, is_active, created_at, updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING parse_rule_id""",
                (name, cat, lt, match, extract, Jsonb(mapping), et, tf, prio, active, at(-20, 11),
                 at(-20, 11) if active else at(0, 10))).fetchone()
        prid[name] = row["parse_rule_id"]
    audit(at(0, 10), "admin", "로그 조회 · 파싱", "UPDATE", "parse_rule", prid["apache combined (구버전)"],
          {"is_active": True}, {"is_active": False}, "파싱 규칙 비활성화: apache combined (구버전)")

    # ── 5. 탐지 규칙 (data.sql 6개 + 사용자 등록 · 수정 · 삭제) ──
    c("UPDATE detection_rule SET created_by=%s, created_at=%s, updated_at=%s", (uid["admin"], at(-20, 12), at(-20, 12)))
    for r in c("SELECT rule_id, name FROM detection_rule ORDER BY rule_id").fetchall():
        audit(at(-20, 12), "admin", "위협 탐지 규칙", "CREATE", "detection_rule", r["rule_id"], None, {"name": r["name"]},
              f"탐지 규칙 등록: {r['name']}")
    c("UPDATE detection_rule SET is_active=FALSE, updated_by=%s, updated_at=%s WHERE rule_id=5", (uid["admin"], at(1, 9, 30)))
    audit(at(1, 9, 30), "admin", "위협 탐지 규칙", "UPDATE", "detection_rule", 5, {"is_active": True}, {"is_active": False},
          "탐지 규칙 비활성화: 감사 로그 설정 변경 · 서비스 중지 (운영 점검 기간)")
    ssh_rule_updated = at(5, 10, 0)
    c("""UPDATE detection_rule SET exceptions=%s, version=2, updated_by=%s, updated_at=%s WHERE rule_id=1""",
      (Jsonb({"source_ip": ["10.0.0.50"], "user_account": ["svc-scanner"]}), uid["analyst01"], ssh_rule_updated))
    audit(ssh_rule_updated, "analyst01", "위협 탐지 규칙", "UPDATE", "detection_rule", 1, {"version": 1, "exceptions": None},
          {"version": 2, "exceptions": {"source_ip": ["10.0.0.50"], "user_account": ["svc-scanner"]}},
          "탐지 규칙 수정: SSH 반복 인증 실패 (v1 → v2, 내부 취약점 스캐너 예외 추가)")
    r7 = c("""INSERT INTO detection_rule (name, description, detect_method, log_type_code, event_type_code, condition_expr,
                                         group_by, time_window_sec, threshold_count, severity, suppress_sec, mitre_technique,
                                         is_active, created_by, created_at, updated_at)
              VALUES ('방화벽 포트 스캔', '짧은 시간 다수 포트 차단', 'THRESHOLD', 'NETWORK', 'fw_deny', '{"all":[]}',
                      'SOURCE_IP', 60, 30, 'HIGH', 1800, 'T1046', TRUE, %s, %s, %s) RETURNING rule_id""",
           (uid["analyst01"], at(3, 16, 0), at(3, 16, 0))).fetchone()["rule_id"]
    audit(at(3, 16, 0), "analyst01", "위협 탐지 규칙", "CREATE", "detection_rule", r7, None,
          {"name": "방화벽 포트 스캔", "condition": "fw_deny > 30회 / 1분 · 출발지 IP"}, "탐지 규칙 등록: 방화벽 포트 스캔")
    r8 = c("""INSERT INTO detection_rule (name, description, detect_method, log_type_code, event_type_code, condition_expr,
                                         severity, is_active, created_by, created_at, updated_by, updated_at, deleted_at)
              VALUES ('테스트 규칙 (404 전체)', '시험용으로 등록했다가 삭제', 'CONDITION', 'WEB', 'http_404', '{"all":[]}',
                      'INFO', TRUE, %s, %s, %s, %s, %s) RETURNING rule_id""",
           (uid["analyst02"], at(2, 15, 0), uid["analyst02"], at(2, 15, 20), at(2, 15, 20))).fetchone()["rule_id"]
    audit(at(2, 15, 0), "analyst02", "위협 탐지 규칙", "CREATE", "detection_rule", r8, None, {"name": "테스트 규칙 (404 전체)"},
          "탐지 규칙 등록: 테스트 규칙 (404 전체)")
    audit(at(2, 15, 20), "analyst02", "위협 탐지 규칙", "DELETE", "detection_rule", r8, {"name": "테스트 규칙 (404 전체)"}, None,
          "탐지 규칙 삭제: 테스트 규칙 (404 전체)")

    # ── 6. 수집 작업 · 업로드 파일 ──
    job = {}

    def add_job(target, method, trig, started, finished, status, file_id=None, cause=None, msg=None):
        return c("""INSERT INTO collect_job (target_id, collect_method, trigger_type, file_id, started_at, finished_at, status,
                                             collected_count, duplicate_count, error_cause, error_message)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,0,%s,%s,%s) RETURNING job_id""",
                 (tid[target], method, trig, file_id, started, finished, status,
                  rnd.randint(0, 6) if status in ("SUCCESS", "RUNNING", "PARTIAL") else 0, cause, msg)).fetchone()["job_id"]

    for d in range(DAYS):
        today = d == DAYS - 1
        for target in ("bastion", "db-01", "was-02", "web-01", "fw-01"):
            partial = target == "was-02" and d == 6
            job[(target, d)] = add_job(
                target, "SYSLOG", "AUTO", at(d, 0), None if today else at(d, 23, 59, 59),
                "RUNNING" if today else "PARTIAL" if partial else "SUCCESS",
                cause="TLS 핸드셰이크 실패" if partial else None,
                msg="certificate has expired (14:02~14:31 수신 중단)" if partial else None)
        if d >= 1:
            fail, partial = d in API_FAIL_DAYS, d in API_PARTIAL_DAYS
            job[("api-gw", d)] = add_job(
                "api-gw", "REST_API", "AUTO", at(d, 2, 0), at(d, 2, 0, 31 if partial else 6),
                "FAIL" if fail else "PARTIAL" if partial else "SUCCESS",
                cause="REST API 인증 실패" if fail else "REST API 응답 시간 초과" if partial else None,
                msg="HTTP 401 Unauthorized (토큰 만료)" if fail else "Read timed out after 30s (2/5 페이지 수집)" if partial else None)
    for d, (h, m) in list(UPLOAD_OK.items()) + [(UPLOAD_FAIL_DAY[0], UPLOAD_FAIL_DAY[1:])]:
        failed = d == UPLOAD_FAIL_DAY[0]
        name = f"ftp_auth_{(START + timedelta(days=d - 1)):%Y%m%d}.log"
        fid = c("""INSERT INTO upload_file (target_id, log_type_code, original_name, stored_path, file_size, sha256, encoding,
                                            uploaded_by, uploaded_at)
                   VALUES (%s,'AUTH',%s,%s,%s,%s,%s,%s,%s) RETURNING file_id""",
                (tid["legacy-ftp"], name, f"uploads/2026/11/{sha(name)[:12]}_{name}", rnd.randint(2000, 9000), sha(name + "f"),
                 None if failed else "UTF-8", uid["analyst02"], at(d, h, m))).fetchone()["file_id"]
        job[("legacy-ftp", d)] = add_job("legacy-ftp", "FILE_UPLOAD", "MANUAL", at(d, h, m), at(d, h, m, 3),
                                         "FAIL" if failed else "SUCCESS", file_id=fid,
                                         cause="문자 인코딩 감지 실패" if failed else None,
                                         msg="파일 인코딩을 판별할 수 없습니다 (UTF-8 · EUC-KR 아님)" if failed else None)

    # ── 7. 원본 로그 · 파싱 결과 · 정규화 이벤트 ──
    recs = build_events()
    n = len(recs)
    raw_ids = [r["v"] for r in c("SELECT nextval('raw_log_raw_log_id_seq') AS v FROM generate_series(1,%s)", (n,)).fetchall()]
    raw_rows, pr_rows, ne_rows = [], [], []
    for r, rid in zip(recs, raw_ids):
        r["raw_id"] = rid
        recv = r["received_at"]
        day = (recv.astimezone(KST) - START).days
        jid = job.get((r["target"], day))
        if r["target"] == "api-gw":
            jid = job.get(("api-gw", day))
        status = {"OK": "SUCCESS", "RETRY": "SUCCESS", "FAIL": "FAIL", "PENDING": "PENDING"}[r["parse"]]
        sender = Gen.ip(r["target"]) if r["target"] not in ("api-gw", "legacy-ftp") else None
        raw_rows.append((rid, recv, tid[r["target"]], jid, dict((t[0], t[3]) for t in TARGETS)[r["target"]], sender,
                         r["raw"], sha(r["raw"]), status))
        if r["parse"] == "PENDING":
            continue
        rule = prid.get(RULE_OF_EVENT.get(r["event_type"])) if r["event_type"] else None
        parsed_at = recv + timedelta(milliseconds=rnd.randint(100, 1500))
        if r["parse"] == "FAIL":
            msg = {"NO_MATCHING_RULE": "NO_MATCHING_RULE: 일치하는 파싱 규칙 없음",
                   "TIME_FORMAT": "TIME_FORMAT: 발생 시각 형식 오류 (2026/13/..)",
                   "MISSING_FIELD": "MISSING_FIELD: 출발지 IP · 사용자 계정 추출 실패"}[r["fail"]]
            pr_rows.append((parsed_at, rid, recv, None if r["fail"] == "NO_MATCHING_RULE" else prid["sshd Failed password"],
                            "FAIL", msg, 1))
            continue
        if r["parse"] == "RETRY":
            pr_rows.append((parsed_at, rid, recv, None, "FAIL", "NO_MATCHING_RULE: 일치하는 파싱 규칙 없음 (규칙 우선순위 오류)", 1))
            parsed_at += timedelta(minutes=rnd.randint(20, 90))
            pr_rows.append((parsed_at, rid, recv, rule, "SUCCESS", None, 2))
        else:
            pr_rows.append((parsed_at, rid, recv, rule, "SUCCESS", None, 1))
        r["parsed_at"] = parsed_at
        ne_rows.append(r)

    ne_rows.sort(key=lambda r: r["event_time"])
    ev_ids = [x["v"] for x in c("SELECT nextval('normalized_event_event_id_seq') AS v FROM generate_series(1,%s)",
                                (len(ne_rows),)).fetchall()]
    ne_data = []
    lt_of = dict((t[0], t[3]) for t in TARGETS)
    et_lt = {k: v for k, v in [(e[0], e[2]) for e in EVENT_TYPE_NEW]}
    et_lt.update({"ssh_auth_failed": "AUTH", "ssh_login_success": "AUTH", "sudo_exec": "AUTH", "user_created": "SYSTEM",
                  "user_deleted": "SYSTEM", "usermod": "SYSTEM", "auditd_stopped": "SYSTEM", "audit_rule_changed": "SYSTEM",
                  "http_403": "WEB"})
    for r, eid in zip(ne_rows, ev_ids):
        doc = {"event_time": r["event_time"].isoformat(), "log_type": et_lt[r["event_type"]], "event_type": r["event_type"],
               "source_ip": r["src"], "dest_ip": r["dst"], "dest_port": r["dport"], "user_account": r["user"],
               "host_name": r["target"], "extra": r["extra"]}
        ne_data.append((eid, r["event_time"], r["raw_id"], r["received_at"], tid[r["target"]], et_lt[r["event_type"]],
                        r["event_type"], r["src"], r["dst"], r["dport"], r["user"], r["target"],
                        None if r["extra"] is None else Jsonb(r["extra"]), Jsonb(doc), r["parsed_at"]))
    with conn.cursor() as cur:
        cur.executemany("""INSERT INTO raw_log (raw_log_id, received_at, target_id, job_id, log_type_code, sender_ip,
                                                raw_message, dedup_hash, parse_status)
                           VALUES (%s,%s,%s,%s,%s,%s::inet,%s,%s,%s)""", raw_rows)
        cur.executemany("""INSERT INTO parse_result (created_at, raw_log_id, raw_received_at, parse_rule_id, status,
                                                     fail_reason, attempt_no)
                           VALUES (%s,%s,%s,%s,%s,%s,%s)""", pr_rows)
        cur.executemany("""INSERT INTO normalized_event (event_id, event_time, raw_log_id, raw_received_at, target_id,
                                                         log_type_code, event_type_code, source_ip, dest_ip, dest_port,
                                                         user_account, host_name, extra, normalized_json, created_at)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s::inet,%s::inet,%s,%s,%s,%s,%s,%s)""", ne_data)
    c("""UPDATE collect_job j SET collected_count = (SELECT count(*) FROM raw_log r WHERE r.job_id = j.job_id)""")
    c("""UPDATE collect_target t SET last_collected_at = (SELECT max(received_at) FROM raw_log r WHERE r.target_id = t.target_id)""")
    conn.commit()
    print(f"원본 로그 {len(raw_rows)} · 파싱 결과 {len(pr_rows)} · 정규화 이벤트 {len(ne_data)}")

    # ── 8. 실제 탐지 엔진 실행 ──
    os.environ.setdefault("DETECTION_ENABLED", "false")
    from alarm import create_app
    from alarm.detect import DetectionEngine
    create_app(start_scheduler=False)
    engine = DetectionEngine(batch_size=200)
    engine.cursor = 0
    result = engine.run_all()
    print("탐지 엔진:", result)

    # ── 9. 탐지 결과를 실제 발생 시각에 맞추기 (엔진은 '지금'으로 기록하므로) ──
    for t in c("SELECT threat_id, rule_id, last_event_time FROM threat_event ORDER BY threat_id").fetchall():
        det = t["last_event_time"] + timedelta(seconds=rnd.randint(3, 12))
        no = f"EVT-{det.astimezone(KST):%Y%m%d}-{t['threat_id']:04d}"
        version = 1 if t["rule_id"] == 1 and det < ssh_rule_updated else None
        c("UPDATE threat_event SET detected_at=%s, threat_no=%s, rule_version=COALESCE(%s, rule_version) WHERE threat_id=%s",
          (det, no, version, t["threat_id"]))
        c("UPDATE alert SET created_at=%s, updated_at=%s WHERE threat_id=%s", (det + timedelta(seconds=1),) * 2 + (t["threat_id"],))
    c("""UPDATE alert_history h SET created_at = a.created_at FROM alert a WHERE h.alert_id = a.alert_id""")

    threats = c("""SELECT t.*, r.name AS rule_name, a.alert_id, a.created_at AS alert_at
                     FROM threat_event t JOIN detection_rule r ON r.rule_id = t.rule_id
                     LEFT JOIN alert a ON a.threat_id = t.threat_id ORDER BY t.detected_at""").fetchall()

    def find(rule_id, day, key=None):
        for t in threats:
            if t["rule_id"] == rule_id and (t["detected_at"].astimezone(KST) - START).days == day and \
                    (key is None or t["group_key"] == key):
                return t
        raise RuntimeError(f"시나리오 위협 없음: rule {rule_id} day {day} {key}")

    # ── 10. 이벤트 흐름 3줄 요약 (No 95–96) ──
    summaries = [
        (find(1, 13, "203.0.113.47"), "외부 IP 203.0.113.47 의 bastion SSH 무차별 대입 (11-05에 이어 재공격)",
         "15:30부터 약 5분간 root · admin 등 계정으로 SSH 인증 실패가 집중 발생\n같은 IP가 11-05 새벽에도 60회 시도한 이력이 있음\n성공한 로그인은 없으며 방화벽 차단 검토 필요"),
        (find(3, 3), "deploy 계정이 db-01에서 sudo로 root 셸 획득",
         "14:12 deploy 계정이 sudo /bin/bash 로 root 셸 실행\n3분 뒤 같은 서버에서 신규 계정 backup2 생성\n권한 상승 후 계정 생성으로 이어진 흐름이라 인시던트로 묶음"),
        (find(7, 9), "외부 IP 203.0.113.99 의 포트 스캔 후 웹 관리자 경로 탐색",
         "03:20 1분간 14개 포트에 80회 접속 시도(방화벽 차단)\n10분 뒤 웹 /admin 경로 403 응답 25회\n정찰 단계 활동으로 판단, IP 차단 권고"),
    ]
    for t, cause, flow in summaries:
        c("UPDATE threat_event SET cause=%s, flow_summary=%s, summary_generated_at=%s WHERE threat_id=%s",
          (cause, flow, t["detected_at"] + timedelta(minutes=2), t["threat_id"]))

    # ── 11. 위험 등급 재정의 (No 102–111) ──
    overrides = [  # 위협, 변경 등급, 사유, 상태, 요청자, 처리자, 처리 의견, 요청 후 경과
        (find(2, 5), "LOW", "정기 점검 작업자(ops)의 사전 공지된 야간 접속", "APPROVED", "analyst01", "admin", "점검 일정 확인함", 40),
        (find(3, 7), "CRITICAL", "권한 상승 직후 wheel 그룹 추가 · 감사 서비스 중지까지 이어짐", "APPROVED", "analyst02", "admin",
         "연쇄 행위 확인, 등급 상향 승인", 25),
        (find(4, 10), "INFO", "계획된 임시 계정 정리 작업", "REJECTED", "analyst02", "admin",
         "변경 요청서 미첨부. 오탐 처리로 대신함", 60),
        (find(6, 13, "198.51.100.230"), "MEDIUM", "같은 IP의 반복 탐색(11-07 · 11-16) 이라 위험도 상향 필요", "PENDING",
         "analyst02", None, None, 0),
    ]
    for t, to_sev, reason, status, req, proc, comment, after_min in overrides:
        req_at = t["detected_at"] + timedelta(minutes=15)
        proc_at = None if proc is None else req_at + timedelta(minutes=after_min)
        oid = c("""INSERT INTO severity_override (threat_id, from_severity, to_severity, reason, status, requested_by,
                                                  requested_at, processed_by, processed_at, process_comment)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING override_id""",
                (t["threat_id"], t["severity"], to_sev, reason, status, uid[req], req_at,
                 uid.get(proc), proc_at, comment)).fetchone()["override_id"]
        if status == "APPROVED":
            c("UPDATE threat_event SET severity=%s WHERE threat_id=%s", (to_sev, t["threat_id"]))
            c("UPDATE alert SET severity=%s WHERE threat_id=%s", (to_sev, t["threat_id"]))
            c("""UPDATE normalized_event n SET severity=%s FROM threat_event_link l
                  WHERE l.threat_id=%s AND n.event_id=l.event_id AND n.event_time=l.event_time""", (to_sev, t["threat_id"]))
        if proc:
            audit(proc_at, proc, "로그 분석 · 위험 등급", "APPROVE" if status == "APPROVED" else "REJECT", "severity_override", oid,
                  {"status": "PENDING", "severity": t["severity"]}, {"status": status, "severity": to_sev if status == "APPROVED" else t["severity"]},
                  f"위험 등급 재정의 {'승인' if status == 'APPROVED' else '반려'}: {t['threat_no']} {t['severity']} → {to_sev}")

    # ── 12. 경보 처리 상태 · 오탐 · 담당자 · 이력 (No 147–150) ──
    fp_threats = {find(2, 5)["threat_id"]: "정기 점검 작업 (사전 공지된 야간 접속)",
                  find(4, 10)["threat_id"]: "계획된 임시 계정 정리 (변경 요청 CR-1107)"}
    end_utc = END.astimezone(UTC)
    hist = []
    for i, t in enumerate(c("""SELECT a.alert_id, a.threat_id, a.created_at FROM alert a ORDER BY a.created_at""").fetchall()):
        age = end_utc - t["created_at"]
        who = "analyst01" if i % 2 == 0 else "analyst02"
        status, last = "NEW", t["created_at"]
        acked = resolved = None
        if age > timedelta(hours=10):
            acked = t["created_at"] + timedelta(minutes=rnd.randint(5, 90))
            hist.append((t["alert_id"], "ASSIGN", None, who, None, uid["admin"], acked - timedelta(minutes=2)))
            hist.append((t["alert_id"], "STATUS", "NEW", "ACK", None, uid[who], acked))
            status, last = "ACK", acked
            if age > timedelta(days=2):
                resolved = acked + timedelta(hours=rnd.randint(1, 6))
                hist.append((t["alert_id"], "COMMENT", None, None,
                             rnd.choice(["출발지 IP 방화벽 차단 완료", "담당자 확인 결과 승인된 작업", "계정 잠금 및 비밀번호 초기화",
                                         "관련 서버 점검 완료, 추가 이상 없음"]), uid[who], resolved - timedelta(minutes=5)))
                hist.append((t["alert_id"], "STATUS", "ACK", "RESOLVED", None, uid[who], resolved))
                status, last = "RESOLVED", resolved
        fp = t["threat_id"] in fp_threats
        if fp:
            fp_at = (acked or t["created_at"]) + timedelta(minutes=3)
            hist.append((t["alert_id"], "FALSE_POSITIVE", "false", "true", fp_threats[t["threat_id"]], uid[who], fp_at))
            last = max(last, fp_at)
        c("""UPDATE alert SET status=%s, is_false_positive=%s, assignee_id=%s, acked_at=%s, resolved_at=%s, updated_at=%s
              WHERE alert_id=%s""", (status, fp, uid[who] if acked else None, acked, resolved, last, t["alert_id"]))
    with conn.cursor() as cur:
        cur.executemany("""INSERT INTO alert_history (alert_id, action, from_value, to_value, comment, actor_id, created_at)
                           VALUES (%s,%s,%s,%s,%s,%s,%s)""", hist)

    # ── 13. 인시던트 [권장·확장] ──
    incidents = [
        ("INC-0001", "203.0.113.47 SSH 무차별 대입 반복", [find(1, 2, "203.0.113.47"), find(1, 13, "203.0.113.47")],
         "OPEN", "analyst01", None),   # 명세서 값 INVESTIGATING(13자)은 status VARCHAR(10)에 들어가지 않아 미사용
        ("INC-0002", "db-01 권한 상승 후 계정 생성", [find(3, 3), find(4, 3)], "CLOSED", "analyst02", 1),
        ("INC-0003", "203.0.113.99 정찰 활동 (포트 스캔 · 관리자 경로 탐색)", [find(7, 9), find(6, 9, "203.0.113.99")],
         "OPEN", None, None),
    ]
    for no, title, ts, status, who, closed_days in incidents:
        sev = max((x["severity"] for x in ts), key=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index)
        created = min(x["detected_at"] for x in ts) + timedelta(minutes=30)
        iid = c("""INSERT INTO incident (incident_no, title, severity, status, assignee_id, created_at, closed_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING incident_id""",
                (no, title, sev, status, uid.get(who), created,
                 None if closed_days is None else created + timedelta(days=closed_days))).fetchone()["incident_id"]
        for x in ts:
            c("UPDATE alert SET incident_id=%s WHERE threat_id=%s", (iid, x["threat_id"]))

    # ── 14. 경보 정책 · 시스템 설정 변경 (No 224–228) ──
    c("""UPDATE alert_policy SET alert_mode='THRESHOLD', threshold_count=3, threshold_window_sec=3600, updated_by=%s,
                                 updated_at=%s WHERE severity='LOW'""", (uid["admin"], at(13, 9, 0)))
    c("UPDATE alert_policy SET updated_at=%s WHERE severity <> 'LOW'", (at(-20, 12),))
    audit(at(13, 9, 0), "admin", "시스템 설정", "UPDATE", "alert_policy", "LOW", {"alert_mode": "IMMEDIATE"},
          {"alert_mode": "THRESHOLD", "threshold_count": 3, "threshold_window_sec": 3600},
          "경보 조건 변경: LOW 등급 즉시 → 1시간 내 3건 이상일 때")
    c("UPDATE system_setting SET updated_at=%s", (at(-20, 12),))
    c("UPDATE system_setting SET updated_by=%s, updated_at=%s WHERE setting_key='log.retention_days'", (uid["admin"], at(0, 11, 0)))
    audit(at(0, 11, 0), "admin", "시스템 설정", "UPDATE", "system_setting", "log.retention_days", {"value": 60}, {"value": 90},
          "로그 보관 기간 변경: 60일 → 90일")
    c("UPDATE system_setting SET updated_by=%s, updated_at=%s WHERE setting_key='detect.default_threshold'", (uid["admin"], at(0, 11, 5)))
    audit(at(0, 11, 5), "admin", "시스템 설정", "UPDATE", "system_setting", "detect.default_threshold", {"value": 5}, {"value": 10},
          "기본 탐지 임계 횟수 변경: 5 → 10")

    # ── 15. 화면 설정 (No 182–186, 214–218) ──
    prefs = [
        ("admin", "DARK", "24H", {"collect_stats": True, "event_stats": True, "trend": True, "severity_ratio": True,
                                  "attack_type_top5": True, "attack_ip_top5": True, "recent_threats": True, "alerts": True},
         {"source_ip": True, "user_account": True, "raw_preview": True}),
        ("analyst01", "LIGHT", "7D", {"collect_stats": False, "event_stats": True, "trend": True, "severity_ratio": True,
                                      "attack_type_top5": True, "attack_ip_top5": True, "recent_threats": True, "alerts": True},
         {"source_ip": True, "user_account": True, "raw_preview": False}),
        ("viewer01", "DARK", "1H", {"collect_stats": True, "event_stats": True, "trend": False, "severity_ratio": False,
                                    "attack_type_top5": False, "attack_ip_top5": False, "recent_threats": True, "alerts": True},
         {"source_ip": False, "user_account": False, "raw_preview": False}),
    ]
    for u, theme, period, widgets, cols in prefs:
        c("""INSERT INTO user_preference (user_id, theme, dashboard_period, dashboard_widgets, list_columns, updated_at)
             VALUES (%s,%s,%s,%s,%s,%s)""", (uid[u], theme, period, Jsonb(widgets), Jsonb(cols), at(4, 10, 0)))

    # ── 16. 시간별 집계 (대시보드 · 보고서용, 완료된 시간대만) ──
    c("""INSERT INTO stat_event_hourly (bucket_hour, target_id, event_type_code, severity, event_count, raw_log_count)
         SELECT date_trunc('hour', event_time), target_id, event_type_code, COALESCE(severity, 'NONE'),
                count(*), count(DISTINCT raw_log_id)
           FROM normalized_event WHERE event_time < date_trunc('hour', %s::timestamptz)
          GROUP BY 1, 2, 3, 4""", (end_utc,))

    # ── 17. 보고서 이력 (No 187–212) ──
    reports = [  # 종류, 기간, 시작, 종료, 항목, 형식, 상태, 생성자, 생성 시각
        ("SECURITY_STATUS", "DAILY", 12, 12, ["EVENT_STATS", "TARGET_LOG_STATS"], "PDF", "DONE", "analyst01", at(13, 9, 10)),
        ("THREAT_ANALYSIS", "WEEKLY", 0, 6, ["SEVERITY_STATS", "ATTACK_TYPE_STATS", "TOP_IP"], "PDF", "DONE", "admin", at(7, 9, 0)),
        ("THREAT_ANALYSIS", "WEEKLY", 0, 6, ["SEVERITY_STATS", "ATTACK_TYPE_STATS", "TOP_IP"], "CSV", "DONE", "admin", at(7, 9, 1)),
        ("SECURITY_STATUS", "WEEKLY", 7, 13, ["EVENT_STATS", "TARGET_LOG_STATS"], "PDF", "RUNNING", "analyst02", end_utc - timedelta(seconds=40)),
        ("SECURITY_STATUS", "DAILY", 10, 10, ["EVENT_STATS"], "CSV", "FAIL", "analyst02", at(11, 8, 30)),
        ("THREAT_ANALYSIS", "MONTHLY", -2, -2, ["SEVERITY_STATS", "ATTACK_TYPE_STATS", "TOP_IP"], "PDF", "DONE", "admin", at(0, 9, 30)),
    ]
    for kind, period, s, e, items, fmt, status, who, t in reports:
        if period == "MONTHLY":
            sd, ed = datetime(2026, 10, 1).date(), datetime(2026, 10, 31).date()
        else:
            sd, ed = (START + timedelta(days=s)).date(), (START + timedelta(days=e)).date()
        path = None if status != "DONE" else f"reports/{sd:%Y/%m}/{kind.lower()}_{period.lower()}_{sd:%Y%m%d}_{ed:%Y%m%d}.{fmt.lower()}"
        c("""INSERT INTO report (report_kind, period_type, start_date, end_date, items, file_format, file_path, file_size,
                                 status, created_by, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
          (kind, period, sd, ed, Jsonb(items), fmt, path, rnd.randint(40_000, 900_000) if path else None,
           status, uid[who], t))

    # ── 18. 서비스 상태 (No 229–233) ──
    c("DELETE FROM service_status")
    for code, name, status, msg, ago in [
        ("SYSLOG_RECEIVER", "Syslog 수신기", "UP", "UDP 514 · TCP 514 · TLS 6514 수신 중", 3),
        ("PARSER", "파싱 엔진", "UP", "대기 5건 (PENDING)", 4),
        ("DETECTOR", "탐지 엔진", "UP", "최근 실행: 정상", 6),
        ("API_COLLECTOR", "API 수집기", "DEGRADED", "api-gw: REST API 인증 실패 (HTTP 401) — 토큰 갱신 필요", 15),
        ("DB", "데이터베이스", "UP", "PostgreSQL 16 정상", 2),
    ]:
        c("""INSERT INTO service_status (service_code, name, status, version, message, last_heartbeat_at)
             VALUES (%s,%s,%s,'0.1.0',%s,%s)""", (code, name, status, msg, end_utc - timedelta(seconds=ago)))

    # ── 19. 관리자 작업 이력 (INSERT 전용) ──
    with conn.cursor() as cur:
        cur.executemany("""INSERT INTO admin_audit_log (created_at, user_id, menu, action, target_table, target_id,
                                                        before_value, after_value, summary, client_ip)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::inet)""",
                        [(t, u, m, a, tb, i, None if b is None else Jsonb(b), None if af is None else Jsonb(af), s, ip)
                         for t, u, m, a, tb, i, b, af, s, ip in sorted(audits, key=lambda x: x[0])])
    conn.commit()

    for table in ["admin_user", "admin_session", "login_history", "admin_audit_log", "collect_target", "upload_file",
                  "collect_job", "raw_log", "parse_rule", "event_type", "parse_result", "normalized_event",
                  "detection_rule", "threat_event", "threat_event_link", "severity_override", "incident", "alert",
                  "alert_history", "alert_policy", "user_preference", "stat_event_hourly", "report", "system_setting",
                  "service_status", "log_type"]:
        print(f"  {table:<20} {c(f'SELECT count(*) AS n FROM {table}').fetchone()['n']:>6}")
    conn.close()


if __name__ == "__main__":
    main()
