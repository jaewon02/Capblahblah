"""탐지 엔진 (WBS 5.2 · No 130–136).

1회 실행 = 마지막으로 처리한 정규화 이벤트 ID 이후의 이벤트를 batch_size 만큼 읽어
활성 규칙과 비교 → 조건 기반 / 반복 행위 탐지 → 위협 이벤트 · 경보 생성.

처리 위치(cursor)는 메모리에만 둔다 (테이블 명세서에 저장 위치가 없음).
서버 기동 시 startup_lookback_min 만큼 과거부터 다시 읽고, 이미 탐지된 이벤트는 건너뛰어 중복을 막는다.
"""
import ipaddress
import logging
import re
import threading
from datetime import timedelta

from . import db, events, rules, threats
from .common import KST, now_utc, truncate

log = logging.getLogger(__name__)

SERVICE_CODE = "DETECTOR"
VERSION = "0.1.0"
IP_FIELDS = {"source_ip", "dest_ip"}


# ───────────── 이벤트 값 꺼내기 ─────────────

class EventView:
    """정규화 이벤트에서 규칙 조건의 field 값을 꺼낸다."""

    __slots__ = ("event",)

    def __init__(self, event):
        self.event = event

    def value(self, field):
        """field(normalized_event 컬럼명 또는 extra.<키>)에 해당하는 값(문자열). 없으면 None."""
        e = self.event
        if field in ("event_type_code", "log_type_code", "source_ip", "dest_ip", "user_account", "host_name"):
            return e[field]
        if field == "target_id":
            return str(e["target_id"])
        if field == "dest_port":
            return None if e["dest_port"] is None else str(e["dest_port"])
        if field and field.startswith("extra."):
            extra = e["extra"] if isinstance(e["extra"], dict) else {}  # 형식 오류는 해당 필드 불일치로 처리
            return rules.as_text(extra.get(field[len("extra."):]))
        return None

    def hour_kst(self):
        """발생 시각의 KST 시(0–23). 운영 시간 판단용."""
        return self.event["event_time"].astimezone(KST).hour


# ───────────── 규칙 컴파일 ─────────────

def _range(text):
    m = rules.RANGE.fullmatch(text or "")
    if not m:
        raise ValueError(f"범위 형식 오류: {text}")
    return int(m.group(1)), int(m.group(2))


def _to_int(s):
    try:
        return None if s is None else int(s.strip())
    except ValueError:
        return None


def _ip_matches(ip, cidr_or_ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr_or_ip, strict=False)
    except ValueError:
        return False  # IP 리터럴이 아니면(호스트명 등) 불일치


def _compile_condition(c):
    field, op = c["field"], c["op"]
    expected = rules.as_text(c.get("value"))

    if op == "eq":
        return lambda v: expected is not None and v.value(field) == expected
    if op == "ne":
        return lambda v: expected is not None and v.value(field) != expected
    if op == "contains":
        def contains(v):
            s = v.value(field)
            return s is not None and expected is not None and expected in s
        return contains
    if op == "regex":
        pattern = re.compile(expected or "")

        def regex(v):
            s = v.value(field)
            return s is not None and pattern.search(s) is not None
        return regex
    if op == "in":
        values = c.get("value")
        allowed = {rules.as_text(x) for x in values} if isinstance(values, list) else set()
        return lambda v: v.value(field) in allowed
    if op in ("between", "not_between"):
        lo, hi = _range(expected)
        inside = op == "between"

        def between(v):
            n = _to_int(v.value(field))
            return n is not None and inside == (lo <= n < hi)
        return between
    if op in ("hour_between", "hour_not_between"):
        # 반열림 구간 [lo, hi): "9-18" → 09:00 ~ 17:59 (KST)
        lo, hi = _range(expected)
        inside = op == "hour_between"
        return lambda v: inside == (lo <= v.hour_kst() < hi)
    raise ValueError(f"지원하지 않는 연산자: {op}")


def _compile_exception(field, values):
    """예외 조건: 필드 값이 목록 중 하나와 같으면(IP 필드는 CIDR 포함) 탐지 제외."""
    ip = field in IP_FIELDS

    def test(v):
        s = v.value(field)
        if s is None:
            return False
        return any(_ip_matches(s, c) if ip else c == s for c in values)
    return test


class CompiledRule:
    """탐지 1회 실행 동안 쓰도록 조건 · 정규식을 미리 컴파일한 규칙."""

    def __init__(self, rule):
        self.rule = rule
        self.conditions = rules.read_conditions(rule["condition_expr"])
        self.condition_tests = [_compile_condition(c) for c in self.conditions]
        self.exception_tests = [_compile_exception(k, v or []) for k, v in (rule["exceptions"] or {}).items()]

    def matches(self, v):
        """이벤트 유형 · 로그 유형 · 조건이 모두 일치하고, 예외 조건에 하나도 걸리지 않으면 True."""
        r, e = self.rule, v.event
        if r["event_type_code"] is not None and r["event_type_code"] != e["event_type_code"]:
            return False
        if r["log_type_code"] is not None and r["log_type_code"] != e["log_type_code"]:
            return False
        return all(t(v) for t in self.condition_tests) and not any(t(v) for t in self.exception_tests)

    def group_key(self, v):
        """그룹 키 (threat_event.group_key, 명세서 예: 203.0.113.47 / deploy@db-01).

        SOURCE_IP → 출발지 IP, USER_ACCOUNT → 계정@호스트, TARGET → 호스트명.
        그룹 기준이 없는 조건 기반 규칙은 호스트명 → 출발지 IP 순으로 사용.
        """
        group = self.rule["group_by"]
        host = v.value("host_name")
        if group is None:
            return host if host is not None else v.value("source_ip")
        if group == "SOURCE_IP":
            return v.value("source_ip")
        if group == "USER_ACCOUNT":
            user = v.value("user_account")
            return None if user is None else (user if host is None else f"{user}@{host}")
        if group == "TARGET":
            return host if host is not None else f"target-{v.value('target_id')}"
        return None


# ───────────── 엔진 ─────────────

class DetectionEngine:

    def __init__(self, batch_size=1000, startup_lookback_min=60):
        self.batch_size = batch_size
        self.startup_lookback_min = startup_lookback_min
        self.cursor = None  # 마지막으로 처리한 event_id. None = 아직 초기화 전
        self._lock = threading.Lock()

    def run_all(self):
        """쌓인 이벤트가 많으면 batch 가 빌 때까지 반복. 실행할 때마다 DETECTOR heartbeat 갱신.

        잠금: 주기 실행과 수동 실행(/api/dev/detect)이 겹쳐 중복 탐지되지 않도록.
        (서버 1대 기준. 여러 대로 늘리면 DB 락 등 분산 잠금 필요)
        """
        with self._lock:
            processed = created = 0
            last = None
            while True:
                with db.transaction() as conn:
                    n, c, last = self._run_once(conn)
                # 트랜잭션 커밋 후에 처리 위치를 옮긴다 (실패하면 옮기지 않아 다음 실행에서 같은 batch 를 다시 처리)
                if last is not None:
                    self.cursor = last
                processed += n
                created += c
                if n < self.batch_size:
                    break

            if created:
                log.info("탐지 완료: 이벤트 %d건 처리, 위협 이벤트 %d건 생성", processed, created)
            heartbeat("UP", f"최근 실행: 이벤트 {processed}건 처리, 위협 이벤트 {created}건 생성")
            return {"processed": processed, "created": created, "lastEventId": last}

    def _run_once(self, conn):
        if self.cursor is None:
            since = now_utc() - timedelta(minutes=self.startup_lookback_min)
            self.cursor = events.cursor_since(conn, since)
        batch = events.find_after(conn, self.cursor, self.batch_size)
        if not batch:
            return 0, 0, None

        views = [EventView(e) for e in batch]
        created = 0
        for rule in self._active_rules(conn):
            hits = [v for v in views if rule.matches(v)]
            if not hits:
                continue
            if rule.rule["detect_method"] == "THRESHOLD":
                created += self._detect_threshold(conn, rule, hits)
            else:
                created += self._detect_condition(conn, rule, hits)
        return len(batch), created, batch[-1]["event_id"]

    def _detect_condition(self, conn, rule, hits):
        """조건 기반 탐지: 일치한 이벤트마다 위협 1건 (중복 억제 시간 안의 같은 그룹 키는 제외)."""
        r = rule.rule
        last_in_batch = {}
        created = 0
        for v in hits:
            e = v.event
            if threats.already_linked(conn, r["rule_id"], e["event_id"]):
                continue
            key = rule.group_key(v)
            if self._suppressed(conn, r, key, e["event_time"], last_in_batch):
                continue
            evidence = {"cond": rules.describe(r, rule.conditions), "observed": _observed(rule, v)}
            threats.create(conn, r, key, [e], _title(r, key, None), evidence)
            last_in_batch[key] = e["event_time"]
            created += 1
        return created

    def _detect_threshold(self, conn, rule, hits):
        """반복 행위 탐지: 그룹 키별로 시간 창 안의 일치 이벤트 수를 세어 임계 횟수 이상이면 위협 1건."""
        r = rule.rule
        by_key = {}
        for v in hits:
            key = rule.group_key(v)
            if key is not None:
                by_key.setdefault(key, []).append(v)

        last_in_batch = {}
        created = 0
        for key, group in by_key.items():
            latest = max(v.event["event_time"] for v in group)
            # 이 시점까지 이미 탐지돼 있으면 건너뜀 (재처리 중복 방지)
            if threats.detected_since(conn, r["rule_id"], key, latest):
                continue

            start = latest - timedelta(seconds=r["time_window_sec"])
            in_window = []
            for e in events.find_in_window(conn, start, latest, r["event_type_code"], r["log_type_code"]):
                v = EventView(e)
                if rule.matches(v) and rule.group_key(v) == key:
                    in_window.append(e)
            count = len(in_window)
            if count <= r["threshold_count"]:  # 임계값 판정: 초과(>) — 기능정의서 No 134 · WBS 5.2.2.1
                continue
            if self._suppressed(conn, r, key, latest, last_in_batch):
                continue

            observed = f"{count}회 / {rules.window_text(r['time_window_sec'])}"
            evidence = {"cond": rules.describe(r, rule.conditions), "observed": observed}
            threats.create(conn, r, key, in_window, _title(r, key, observed), evidence)
            last_in_batch[key] = latest
            created += 1
        return created

    @staticmethod
    def _suppressed(conn, r, key, at, last_in_batch):
        """suppress_sec(명세서 기본 0) 안에 같은 규칙 · 같은 그룹 키로 탐지된 건이 있으면 새로 만들지 않음."""
        sec = r["suppress_sec"]
        if sec <= 0:
            return False
        since = at - timedelta(seconds=sec)
        prev = last_in_batch.get(key)
        if prev is not None and prev >= since:
            return True
        return threats.detected_since(conn, r["rule_id"], key, since)

    @staticmethod
    def _active_rules(conn):
        compiled = []
        for r in rules.active_rules(conn):
            try:
                compiled.append(CompiledRule(r))
            except (ValueError, re.error, TypeError, AttributeError, KeyError) as e:
                # 잘못 저장된 규칙 하나 때문에 전체 탐지가 멈추지 않도록 건너뛴다
                log.error("탐지 규칙 #%s '%s' 조건 오류로 건너뜀: %s", r["rule_id"], r["name"], e)
        return compiled


def _title(r, key, observed):
    """alert.title (탐지 내용)"""
    t = r["name"] + ("" if key is None else f" — {key}")
    return t if observed is None else f"{t} ({observed})"


def _observed(rule, v):
    """조건 기반 탐지의 관측값: 조건 필드의 실제 값. 예: "extra.COMMAND=/bin/bash" """
    if not rule.conditions:
        return v.event["event_type_code"]
    def text(c):
        if c["field"] == "event_time":
            return f"시각={v.hour_kst()}시"
        value = v.value(c["field"])
        return f"{c['field']}={'-' if value is None else value}"
    return ", ".join(text(c) for c in rule.conditions)


def heartbeat(status, message):
    """service_status 의 DETECTOR 갱신 (명세서 TB_26, No 229–233)."""
    try:
        with db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO service_status (service_code, name, status, version, message, last_heartbeat_at)
                VALUES (%s, '탐지 엔진', %s, %s, %s, now())
                ON CONFLICT (service_code) DO UPDATE
                   SET status = EXCLUDED.status, version = EXCLUDED.version,
                       message = EXCLUDED.message, last_heartbeat_at = EXCLUDED.last_heartbeat_at
                """, (SERVICE_CODE, status, VERSION, truncate(message, 300)))
    except Exception as e:  # noqa: BLE001 — 상태 기록 실패가 탐지를 멈추면 안 된다
        log.warning("service_status 갱신 실패: %s", e)


# ───────────── 주기 실행 ─────────────

class DetectionScheduler:
    """탐지 엔진을 interval 초 간격(이전 실행이 끝난 뒤부터)으로 실행하는 백그라운드 스레드."""

    def __init__(self, engine, interval_sec, initial_delay_sec=5):
        self.engine = engine
        self.interval_sec = interval_sec
        self.initial_delay_sec = initial_delay_sec
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="detection-scheduler", daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        if self._stop.wait(self.initial_delay_sec):
            return
        while True:
            try:
                self.engine.run_all()
            except Exception as e:  # noqa: BLE001
                log.exception("탐지 엔진 실행 실패")
                heartbeat("DEGRADED", f"탐지 실패: {e}")
            if self._stop.wait(self.interval_sec):
                return
