-- 경보기 SIEM — 테이블 명세서 v0.1 (2026-10-29) 기준 DDL · PostgreSQL 16
-- 26개 테이블 (TB_01 ~ TB_26). 명세서의 컬럼 · 타입 · PK · FK · NN · UQ · 기본값 · CHECK · INDEX를 그대로 옮김.
-- 실행: psql -U siem -d siem -v ON_ERROR_STOP=1 -f schema.sql   (FK 참조 순서대로 생성)

-- 명세서 개요 '시간 기준': TIMESTAMPTZ(UTC) 저장 → 파티션 경계도 UTC 기준으로 계산되도록
SET TIME ZONE 'UTC';

-- ═════════════════ 인증 · 관리자 ═════════════════

-- TB_01 admin_user · 관리자 계정
CREATE TABLE admin_user (
    user_id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login_id            VARCHAR(50)  NOT NULL UNIQUE,
    password_hash       VARCHAR(255) NOT NULL,
    display_name        VARCHAR(50)  NOT NULL,
    role                VARCHAR(20)  NOT NULL DEFAULT 'ANALYST',
    failed_login_count  SMALLINT     NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    mfa_secret_enc      BYTEA,
    last_login_at       TIMESTAMPTZ,
    is_active           BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (role IN ('ADMIN','ANALYST','VIEWER'))
);

-- TB_02 admin_session · 로그인 세션
CREATE TABLE admin_session (
    session_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash       CHAR(64)     NOT NULL UNIQUE,
    user_id          BIGINT       NOT NULL REFERENCES admin_user (user_id),
    client_ip        INET         NOT NULL,
    user_agent       VARCHAR(500),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_activity_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ  NOT NULL,
    revoked_at       TIMESTAMPTZ
);
CREATE INDEX ix_admin_session_user ON admin_session (user_id, revoked_at);

-- TB_03 login_history · 로그인 이력
CREATE TABLE login_history (
    history_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        BIGINT       REFERENCES admin_user (user_id),
    input_login_id VARCHAR(50)  NOT NULL,
    client_ip      INET         NOT NULL,
    result         VARCHAR(20)  NOT NULL,
    fail_reason    VARCHAR(50),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (result IN ('SUCCESS','FAIL','LOCKED','LOGOUT','EXPIRED'))
);
CREATE INDEX ix_login_history_time ON login_history (created_at DESC);
CREATE INDEX ix_login_history_ip   ON login_history (client_ip, created_at DESC);

-- TB_04 admin_audit_log · 관리자 작업 이력 (INSERT 전용 — 파일 끝 REVOKE 참고)
CREATE TABLE admin_audit_log (
    audit_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id      BIGINT       REFERENCES admin_user (user_id),
    menu         VARCHAR(50)  NOT NULL,
    action       VARCHAR(20)  NOT NULL,
    target_table VARCHAR(50),
    target_id    VARCHAR(50),
    before_value JSONB,
    after_value  JSONB,
    summary      VARCHAR(500) NOT NULL,
    client_ip    INET,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_time   ON admin_audit_log (created_at DESC);
CREATE INDEX ix_audit_target ON admin_audit_log (target_table, target_id);

-- ═════════════════ 로그 수집 ═════════════════

-- TB_05 log_type · 로그 유형 코드
CREATE TABLE log_type (
    log_type_code VARCHAR(20) PRIMARY KEY,
    name          VARCHAR(50) NOT NULL,
    sort_order    SMALLINT    NOT NULL DEFAULT 0
);

-- TB_06 collect_target · 수집 대상
CREATE TABLE collect_target (
    target_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name               VARCHAR(100) NOT NULL,
    ip_address         INET         NOT NULL,
    description        VARCHAR(500),
    log_type_code      VARCHAR(20)  NOT NULL REFERENCES log_type (log_type_code),
    collect_method     VARCHAR(20)  NOT NULL,
    syslog_protocol    VARCHAR(10),
    syslog_port        INTEGER,
    api_url            VARCHAR(500),
    api_credential_ref VARCHAR(200),
    collect_cron       VARCHAR(50),
    is_active          BOOLEAN      NOT NULL DEFAULT TRUE,
    last_collected_at  TIMESTAMPTZ,
    created_by         BIGINT       REFERENCES admin_user (user_id),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ,
    CHECK (collect_method IN ('SYSLOG','REST_API','FILE_UPLOAD'))
);
CREATE UNIQUE INDEX uq_collect_target_name ON collect_target (name) WHERE deleted_at IS NULL;

-- TB_07 upload_file · 업로드 파일
CREATE TABLE upload_file (
    file_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_id     BIGINT       NOT NULL REFERENCES collect_target (target_id),
    log_type_code VARCHAR(20)  NOT NULL REFERENCES log_type (log_type_code),
    original_name VARCHAR(255) NOT NULL,
    stored_path   VARCHAR(500) NOT NULL,
    file_size     BIGINT       NOT NULL,
    sha256        CHAR(64)     NOT NULL,
    encoding      VARCHAR(20),
    uploaded_by   BIGINT       NOT NULL REFERENCES admin_user (user_id),
    uploaded_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- TB_08 collect_job · 수집 작업(이력)
CREATE TABLE collect_job (
    job_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_id       BIGINT       NOT NULL REFERENCES collect_target (target_id),
    collect_method  VARCHAR(20)  NOT NULL,
    trigger_type    VARCHAR(10)  NOT NULL,
    file_id         BIGINT       REFERENCES upload_file (file_id),
    started_at      TIMESTAMPTZ  NOT NULL,
    finished_at     TIMESTAMPTZ,
    status          VARCHAR(10)  NOT NULL,
    collected_count INTEGER      NOT NULL DEFAULT 0,
    duplicate_count INTEGER      NOT NULL DEFAULT 0,
    error_cause     VARCHAR(200),
    error_message   TEXT,
    CHECK (status IN ('RUNNING','SUCCESS','PARTIAL','FAIL')),
    CHECK (trigger_type IN ('AUTO','MANUAL'))
);
CREATE INDEX ix_collect_job_target_time ON collect_job (target_id, started_at DESC);
CREATE INDEX ix_collect_job_fail ON collect_job (started_at DESC) WHERE status IN ('FAIL','PARTIAL');

-- TB_09 raw_log · 원본 로그 (월 단위 RANGE 파티션)
CREATE TABLE raw_log (
    raw_log_id    BIGSERIAL    NOT NULL,
    received_at   TIMESTAMPTZ  NOT NULL,
    target_id     BIGINT       NOT NULL REFERENCES collect_target (target_id),
    job_id        BIGINT       REFERENCES collect_job (job_id),
    log_type_code VARCHAR(20)  NOT NULL REFERENCES log_type (log_type_code),
    sender_ip     INET,
    raw_message   TEXT         NOT NULL,
    dedup_hash    CHAR(64)     NOT NULL,
    parse_status  VARCHAR(10)  NOT NULL DEFAULT 'PENDING',
    PRIMARY KEY (raw_log_id, received_at),
    CHECK (parse_status IN ('PENDING','SUCCESS','FAIL'))
) PARTITION BY RANGE (received_at);
CREATE INDEX ix_raw_log_dedup       ON raw_log (target_id, dedup_hash);
CREATE INDEX ix_raw_log_target_time ON raw_log (target_id, received_at DESC);
CREATE INDEX ix_raw_log_pending     ON raw_log (received_at) WHERE parse_status = 'PENDING';

-- ═════════════════ 파싱 · 정규화 ═════════════════

-- TB_11 event_type · 이벤트 유형 코드 (parse_rule이 참조하므로 먼저 생성)
CREATE TABLE event_type (
    event_type_code  VARCHAR(50)  PRIMARY KEY,
    name             VARCHAR(100) NOT NULL,
    log_type_code    VARCHAR(20)  NOT NULL REFERENCES log_type (log_type_code),
    attack_type      VARCHAR(50),
    mitre_technique  VARCHAR(20),
    default_severity VARCHAR(10),
    CHECK (default_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'))
);

-- TB_10 parse_rule · 파싱 규칙
CREATE TABLE parse_rule (
    parse_rule_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            VARCHAR(100) NOT NULL UNIQUE,
    category        VARCHAR(30)  NOT NULL,
    log_type_code   VARCHAR(20)  NOT NULL REFERENCES log_type (log_type_code),
    match_pattern   TEXT         NOT NULL,
    extract_pattern TEXT         NOT NULL,
    field_mapping   JSONB        NOT NULL,
    event_type_code VARCHAR(50)  REFERENCES event_type (event_type_code),
    time_format     VARCHAR(50),
    priority        SMALLINT     NOT NULL DEFAULT 100,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- TB_12 parse_result · 파싱 결과 로그 (월 단위 RANGE 파티션)
CREATE TABLE parse_result (
    parse_result_id BIGSERIAL    NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    raw_log_id      BIGINT       NOT NULL,
    raw_received_at TIMESTAMPTZ  NOT NULL,
    parse_rule_id   BIGINT       REFERENCES parse_rule (parse_rule_id),
    status          VARCHAR(10)  NOT NULL,
    fail_reason     VARCHAR(200),
    attempt_no      SMALLINT     NOT NULL DEFAULT 1,
    PRIMARY KEY (parse_result_id, created_at)
) PARTITION BY RANGE (created_at);
CREATE INDEX ix_parse_result_raw  ON parse_result (raw_log_id);
CREATE INDEX ix_parse_result_fail ON parse_result (created_at DESC) WHERE status = 'FAIL';

-- TB_13 normalized_event · 정규화 이벤트 (월 단위 RANGE 파티션)
CREATE TABLE normalized_event (
    event_id        BIGSERIAL    NOT NULL,
    event_time      TIMESTAMPTZ  NOT NULL,
    raw_log_id      BIGINT       NOT NULL,
    raw_received_at TIMESTAMPTZ  NOT NULL,
    target_id       BIGINT       NOT NULL REFERENCES collect_target (target_id),
    log_type_code   VARCHAR(20)  NOT NULL REFERENCES log_type (log_type_code),
    event_type_code VARCHAR(50)  NOT NULL REFERENCES event_type (event_type_code),
    source_ip       INET,
    dest_ip         INET,
    dest_port       INTEGER,
    user_account    VARCHAR(100),
    host_name       VARCHAR(100),
    severity        VARCHAR(10),
    extra           JSONB,
    normalized_json JSONB        NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, event_time),
    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'))
) PARTITION BY RANGE (event_time);
CREATE INDEX ix_event_time     ON normalized_event (event_time DESC);
CREATE INDEX ix_event_src_ip   ON normalized_event (source_ip, event_time DESC);
CREATE INDEX ix_event_user     ON normalized_event (user_account, event_time DESC);
CREATE INDEX ix_event_type     ON normalized_event (event_type_code, event_time DESC);
CREATE INDEX ix_event_severity ON normalized_event (severity, event_time DESC) WHERE severity IS NOT NULL;

-- ═════════════════ 탐지 · 분석 ═════════════════

-- TB_14 detection_rule · 탐지 규칙
CREATE TABLE detection_rule (
    rule_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            VARCHAR(100) NOT NULL,
    description     VARCHAR(500),
    detect_method   VARCHAR(20)  NOT NULL,
    log_type_code   VARCHAR(20)  REFERENCES log_type (log_type_code),
    event_type_code VARCHAR(50)  REFERENCES event_type (event_type_code),
    condition_expr  JSONB        NOT NULL,
    group_by        VARCHAR(20),
    time_window_sec INTEGER,
    threshold_count INTEGER,
    severity        VARCHAR(10)  NOT NULL,
    suppress_sec    INTEGER      NOT NULL DEFAULT 0,
    exceptions      JSONB,
    mitre_technique VARCHAR(20),
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    version         INTEGER      NOT NULL DEFAULT 1,
    created_by      BIGINT       REFERENCES admin_user (user_id),
    updated_by      BIGINT       REFERENCES admin_user (user_id),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CHECK (detect_method IN ('CONDITION','THRESHOLD')),
    CHECK (detect_method <> 'THRESHOLD' OR (time_window_sec > 0 AND threshold_count > 0 AND group_by IS NOT NULL)),
    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'))
);

-- TB_15 threat_event · 위협 이벤트(탐지 결과)
CREATE TABLE threat_event (
    threat_id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    threat_no            VARCHAR(30)  NOT NULL UNIQUE,
    rule_id              BIGINT       NOT NULL REFERENCES detection_rule (rule_id),
    rule_version         INTEGER      NOT NULL,
    detected_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    first_event_time     TIMESTAMPTZ  NOT NULL,
    last_event_time      TIMESTAMPTZ  NOT NULL,
    group_key            VARCHAR(200),
    source_ip            INET,
    user_account         VARCHAR(100),
    target_id            BIGINT       REFERENCES collect_target (target_id),
    log_type_code        VARCHAR(20)  NOT NULL REFERENCES log_type (log_type_code),
    event_count          INTEGER      NOT NULL DEFAULT 1,
    severity             VARCHAR(10)  NOT NULL,
    original_severity    VARCHAR(10)  NOT NULL,
    evidence             JSONB        NOT NULL,
    cause                VARCHAR(500),
    flow_summary         TEXT,
    summary_generated_at TIMESTAMPTZ,
    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    CHECK (original_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'))
);
CREATE INDEX ix_threat_detected ON threat_event (detected_at DESC);
CREATE INDEX ix_threat_severity ON threat_event (severity, detected_at DESC);
CREATE INDEX ix_threat_src_ip   ON threat_event (source_ip, detected_at DESC);
CREATE INDEX ix_threat_user     ON threat_event (user_account, detected_at DESC);
CREATE INDEX ix_threat_rule     ON threat_event (rule_id, detected_at DESC);

-- TB_16 threat_event_link · 위협 이벤트-관련 로그 연결
CREATE TABLE threat_event_link (
    threat_id  BIGINT      NOT NULL REFERENCES threat_event (threat_id),
    event_id   BIGINT      NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    raw_log_id BIGINT      NOT NULL,
    PRIMARY KEY (threat_id, event_id)
);

-- TB_17 severity_override · 위험 등급 재정의 요청
CREATE TABLE severity_override (
    override_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    threat_id       BIGINT        NOT NULL REFERENCES threat_event (threat_id),
    from_severity   VARCHAR(10)   NOT NULL,
    to_severity     VARCHAR(10)   NOT NULL,
    reason          VARCHAR(1000) NOT NULL,
    status          VARCHAR(10)   NOT NULL DEFAULT 'PENDING',
    requested_by    BIGINT        NOT NULL REFERENCES admin_user (user_id),
    requested_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),
    processed_by    BIGINT        REFERENCES admin_user (user_id),
    processed_at    TIMESTAMPTZ,
    process_comment VARCHAR(500),
    CHECK (status IN ('PENDING','APPROVED','REJECTED')),
    CHECK (from_severity <> to_severity),
    CHECK (processed_by IS NULL OR processed_by <> requested_by),
    CHECK (from_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    CHECK (to_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'))
);
CREATE UNIQUE INDEX uq_override_pending ON severity_override (threat_id) WHERE status = 'PENDING';
CREATE INDEX ix_override_status ON severity_override (status, requested_at DESC);

-- ═════════════════ 경보 ═════════════════

-- TB_21 incident · 인시던트 [권장·확장] (alert가 참조하므로 먼저 생성)
CREATE TABLE incident (
    incident_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_no VARCHAR(20)  NOT NULL UNIQUE,
    title       VARCHAR(300) NOT NULL,
    severity    VARCHAR(10)  NOT NULL,
    status      VARCHAR(10)  NOT NULL DEFAULT 'OPEN',
    assignee_id BIGINT       REFERENCES admin_user (user_id),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    closed_at   TIMESTAMPTZ,
    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'))
);

-- TB_18 alert · 경보
CREATE TABLE alert (
    alert_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_no          VARCHAR(20)  NOT NULL UNIQUE,
    threat_id         BIGINT       NOT NULL UNIQUE REFERENCES threat_event (threat_id),
    severity          VARCHAR(10)  NOT NULL,
    title             VARCHAR(300) NOT NULL,
    status            VARCHAR(10)  NOT NULL DEFAULT 'NEW',
    is_false_positive BOOLEAN      NOT NULL DEFAULT FALSE,
    assignee_id       BIGINT       REFERENCES admin_user (user_id),
    incident_id       BIGINT       REFERENCES incident (incident_id),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    acked_at          TIMESTAMPTZ,
    resolved_at       TIMESTAMPTZ,
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (status IN ('NEW','ACK','RESOLVED')),
    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'))
);
CREATE INDEX ix_alert_created  ON alert (created_at DESC);
CREATE INDEX ix_alert_status   ON alert (status, created_at DESC);
CREATE INDEX ix_alert_severity ON alert (severity, created_at DESC);

-- TB_19 alert_history · 경보 처리 이력
CREATE TABLE alert_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id   BIGINT        NOT NULL REFERENCES alert (alert_id),
    action     VARCHAR(20)   NOT NULL,
    from_value VARCHAR(50),
    to_value   VARCHAR(50),
    comment    VARCHAR(1000),
    actor_id   BIGINT        REFERENCES admin_user (user_id),
    created_at TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE INDEX ix_alert_history_alert ON alert_history (alert_id, created_at);

-- TB_20 alert_policy · 경보 발생 정책 (등급별 1행, 5행 고정)
CREATE TABLE alert_policy (
    severity             VARCHAR(10) PRIMARY KEY,
    alert_mode           VARCHAR(20) NOT NULL,
    threshold_count      INTEGER,
    threshold_window_sec INTEGER,
    updated_by           BIGINT      REFERENCES admin_user (user_id),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (alert_mode IN ('IMMEDIATE','THRESHOLD','NONE')),
    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'))
);

-- ═════════════════ 대시보드 · 보고서 ═════════════════

-- TB_22 user_preference · 사용자 화면 설정
CREATE TABLE user_preference (
    user_id           BIGINT      PRIMARY KEY REFERENCES admin_user (user_id),
    theme             VARCHAR(10) NOT NULL DEFAULT 'DARK',
    dashboard_period  VARCHAR(5)  NOT NULL DEFAULT '24H',
    dashboard_widgets JSONB       NOT NULL DEFAULT '{}'::jsonb,
    list_columns      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- TB_23 stat_event_hourly · 시간별 이벤트 집계
CREATE TABLE stat_event_hourly (
    bucket_hour     TIMESTAMPTZ NOT NULL,
    target_id       BIGINT      NOT NULL REFERENCES collect_target (target_id),
    event_type_code VARCHAR(50) NOT NULL REFERENCES event_type (event_type_code),
    severity        VARCHAR(10) NOT NULL,
    event_count     INTEGER     NOT NULL DEFAULT 0,
    raw_log_count   INTEGER     NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_hour, target_id, event_type_code, severity),
    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','NONE'))
);

-- TB_24 report · 보고서 생성 이력
CREATE TABLE report (
    report_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    report_kind VARCHAR(20)  NOT NULL,
    period_type VARCHAR(10)  NOT NULL,
    start_date  DATE         NOT NULL,
    end_date    DATE         NOT NULL,
    items       JSONB        NOT NULL,
    file_format VARCHAR(5)   NOT NULL,
    file_path   VARCHAR(500),
    file_size   BIGINT,
    status      VARCHAR(10)  NOT NULL DEFAULT 'DONE',
    created_by  BIGINT       NOT NULL REFERENCES admin_user (user_id),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (end_date >= start_date),
    CHECK (file_format IN ('PDF','CSV'))
);
CREATE INDEX ix_report_created ON report (created_at DESC);

-- ═════════════════ 시스템 설정 ═════════════════

-- TB_25 system_setting · 시스템 설정값
CREATE TABLE system_setting (
    setting_key   VARCHAR(100) PRIMARY KEY,
    setting_value JSONB        NOT NULL,
    description   VARCHAR(300),
    updated_by    BIGINT       REFERENCES admin_user (user_id),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- TB_26 service_status · 서비스 상태
CREATE TABLE service_status (
    service_code      VARCHAR(30)  PRIMARY KEY,
    name              VARCHAR(50)  NOT NULL,
    status            VARCHAR(10)  NOT NULL,
    version           VARCHAR(20),
    message           VARCHAR(300),
    last_heartbeat_at TIMESTAMPTZ  NOT NULL
);

-- ═════════════════ 월 단위 파티션 ═════════════════
-- 명세서: raw_log · parse_result · normalized_event 월 단위 RANGE 파티션, 보관 기간 경과 시 파티션 DROP.
-- 아래는 2026-10 ~ 2027-03 초기 파티션. 다음 달 파티션 자동 생성 · 경과 파티션 DROP은 WBS 2.6(파티션 · 보관 정책)에서 처리.
DO $$
DECLARE
    m DATE;
BEGIN
    FOR m IN SELECT generate_series(DATE '2026-10-01', DATE '2027-03-01', INTERVAL '1 month')::date LOOP
        EXECUTE format('CREATE TABLE raw_log_%s PARTITION OF raw_log FOR VALUES FROM (%L) TO (%L)',
                       to_char(m, 'YYYY_MM'), m, (m + INTERVAL '1 month')::date);
        EXECUTE format('CREATE TABLE parse_result_%s PARTITION OF parse_result FOR VALUES FROM (%L) TO (%L)',
                       to_char(m, 'YYYY_MM'), m, (m + INTERVAL '1 month')::date);
        EXECUTE format('CREATE TABLE normalized_event_%s PARTITION OF normalized_event FOR VALUES FROM (%L) TO (%L)',
                       to_char(m, 'YYYY_MM'), m, (m + INTERVAL '1 month')::date);
    END LOOP;
END $$;

-- ═════════════════ 권한 ═════════════════
-- 명세서 개요 '보안': admin_audit_log 는 INSERT 전용 (애플리케이션 DB 계정에 UPDATE/DELETE 권한 미부여)
REVOKE UPDATE, DELETE, TRUNCATE ON admin_audit_log FROM CURRENT_USER;
