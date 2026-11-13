"""PostgreSQL 연결 풀 (psycopg 3).

파티션 테이블(raw_log · normalized_event)은 복합 PK라 ORM 없이 SQL로 직접 다룬다.
사용법:
    with db.transaction() as conn:
        conn.execute(...)
블록이 정상 종료되면 COMMIT, 예외가 나면 ROLLBACK.
"""
from contextlib import contextmanager

from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

_pool = None


def init(config):
    global _pool
    conninfo = make_conninfo(
        host=config["DB_HOST"], port=config["DB_PORT"], dbname=config["DB_NAME"],
        user=config["DB_USERNAME"], password=config["DB_PASSWORD"],
    )
    # 명세서 '시간 기준': TIMESTAMPTZ(UTC) 저장 → 세션 시간대도 UTC
    _pool = ConnectionPool(
        conninfo,
        min_size=1,
        max_size=10,
        timeout=5,  # DB에 연결하지 못하면 5초 뒤 오류 (화면이 오래 멈추지 않도록)
        kwargs={"row_factory": dict_row, "options": "-c TimeZone=UTC"},
        open=True,
    )


@contextmanager
def transaction():
    with _pool.connection() as conn:
        yield conn


def jsonb(value):
    """dict/list → JSONB 파라미터. None 은 NULL."""
    return None if value is None else Jsonb(value)
