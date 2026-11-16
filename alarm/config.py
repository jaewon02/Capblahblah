"""설정값. 모두 환경변수로 바꿀 수 있다."""
import os


def _bool(name, default):
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


class Config:
    # DBMS: PostgreSQL 16 (테이블 명세서 개요). 스키마는 db/schema.sql · data.sql 을 먼저 적용.
    DB_HOST = os.environ.get("DB_HOST", "localhost")
    DB_PORT = int(os.environ.get("DB_PORT", "5432"))
    DB_NAME = os.environ.get("DB_NAME", "siem")
    DB_USERNAME = os.environ.get("DB_USERNAME", "siem")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

    # dev: /api/dev/** (테스트 이벤트 생성 · 탐지 즉시 실행) 활성화. 운영은 APP_PROFILE=prod
    PROFILE = os.environ.get("APP_PROFILE", "dev")

    # 탐지 엔진: 실행 주기(초), 1회 읽는 이벤트 수, 기동 시 다시 확인할 과거 범위(분)
    DETECTION_ENABLED = _bool("DETECTION_ENABLED", True)
    DETECTION_INTERVAL_SEC = float(os.environ.get("DETECTION_INTERVAL_SEC", "10"))
    DETECTION_BATCH_SIZE = int(os.environ.get("DETECTION_BATCH_SIZE", "1000"))
    DETECTION_STARTUP_LOOKBACK_MIN = int(os.environ.get("DETECTION_STARTUP_LOOKBACK_MIN", "60"))
