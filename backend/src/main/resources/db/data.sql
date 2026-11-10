-- 초기 데이터 · schema.sql 다음에 실행
-- [명세서 '코드 정의' 시트 값]  log_type, system_setting 초기값
-- [명세서에 값이 없어 임시로 넣은 값]  alert_policy, event_type, detection_rule
--   → 각각 WBS 3.9(경보 설정) · 2.7(코드 정의서 · 탐지 규칙 목록) 확정 시 교체

-- 로그 유형 (코드 정의: AUTH 인증 · SYSTEM 시스템 · NETWORK 네트워크 · WEB 웹)
INSERT INTO log_type (log_type_code, name, sort_order) VALUES
    ('AUTH', '인증', 1),
    ('SYSTEM', '시스템', 2),
    ('NETWORK', '네트워크', 3),
    ('WEB', '웹', 4);

-- system_setting 초기값 (코드 정의 시트 29~38행)
INSERT INTO system_setting (setting_key, setting_value, description) VALUES
    ('log.retention_days',          '90',      '원본 로그 보관 기간(일). 경과 파티션 DROP'),
    ('log.purge_time',              '"03:00"', '보관 기간 경과 로그 삭제 실행 시각'),
    ('auth.session_idle_min',       '30',      '미사용 시 자동 로그아웃(분)'),
    ('auth.lock_fail_count',        '5',       '연속 실패 허용 횟수'),
    ('auth.lock_minutes',           '15',      '로그인 제한 시간(분)'),
    ('auth.password_min_length',    '10',      '비밀번호 최소 길이(영문·숫자·특수문자 조합)'),
    ('detect.default_window_sec',   '300',     '기본 탐지 시간 창'),
    ('detect.default_threshold',    '10',      '기본 탐지 임계 횟수');

-- 경보 발생 정책 5행 (등급별 1행). 코드 정의 'INFO = 경보 대상 아님(기본)' 에 따라 INFO만 NONE
INSERT INTO alert_policy (severity, alert_mode) VALUES
    ('CRITICAL', 'IMMEDIATE'),
    ('HIGH',     'IMMEDIATE'),
    ('MEDIUM',   'IMMEDIATE'),
    ('LOW',      'IMMEDIATE'),
    ('INFO',     'NONE');

-- 이벤트 유형 (LO_02_01 탐지 대상 5종에 필요한 유형)
INSERT INTO event_type (event_type_code, name, log_type_code) VALUES
    ('ssh_auth_failed',    'SSH 인증 실패',     'AUTH'),
    ('ssh_login_success',  'SSH 로그인 성공',   'AUTH'),
    ('sudo_exec',          'sudo 명령 실행',    'AUTH'),
    ('user_created',       '사용자 계정 생성',  'SYSTEM'),
    ('user_deleted',       '사용자 계정 삭제',  'SYSTEM'),
    ('usermod',            '사용자 권한 변경',  'SYSTEM'),
    ('auditd_stopped',     '감사 서비스 중지',  'SYSTEM'),
    ('audit_rule_changed', '감사 규칙 변경',    'SYSTEM'),
    ('http_403',           'HTTP 403 응답',     'WEB');

-- 기본 탐지 규칙: 기능정의서 시트1 LO_02_01 탐지 대상 5종 + 목업의 '웹 관리자 경로 403 반복'
-- condition_expr 형식은 명세서 예시 {"all":[{"field","op","value"}]}
INSERT INTO detection_rule (name, description, detect_method, log_type_code, event_type_code, condition_expr,
                            group_by, time_window_sec, threshold_count, severity, suppress_sec, mitre_technique, is_active)
VALUES
    ('SSH 반복 인증 실패', '무차별 대입 시도', 'THRESHOLD', 'AUTH', 'ssh_auth_failed',
     '{"all":[]}', 'SOURCE_IP', 300, 10, 'CRITICAL', 600, 'T1110', TRUE),
    ('운영 시간 외 로그인', '운영 시간(09–18시) 외 접속', 'CONDITION', 'AUTH', 'ssh_login_success',
     '{"all":[{"field":"event_time","op":"hour_not_between","value":"9-18"}]}',
     'USER_ACCOUNT', NULL, NULL, 'MEDIUM', 3600, 'T1078', TRUE),
    ('sudo root 셸 실행', '관리자 권한 상승', 'CONDITION', 'AUTH', 'sudo_exec',
     '{"all":[{"field":"extra.USER","op":"eq","value":"root"},{"field":"extra.COMMAND","op":"regex","value":"/bin/(ba)?sh"}]}',
     'USER_ACCOUNT', NULL, NULL, 'HIGH', 0, 'T1548', TRUE),
    ('사용자 계정 생성 · 삭제 · 권한 변경', '계정 변경 감시', 'CONDITION', 'SYSTEM', NULL,
     '{"all":[{"field":"event_type_code","op":"in","value":["user_created","user_deleted","usermod"]}]}',
     'TARGET', NULL, NULL, 'HIGH', 0, 'T1136', TRUE),
    ('감사 로그 설정 변경 · 서비스 중지', 'auditd 무력화', 'CONDITION', 'SYSTEM', NULL,
     '{"all":[{"field":"event_type_code","op":"in","value":["auditd_stopped","audit_rule_changed"]}]}',
     'TARGET', NULL, NULL, 'CRITICAL', 0, 'T1562', FALSE),
    ('웹 관리자 경로 403 반복', '관리자 페이지 탐색', 'THRESHOLD', 'WEB', 'http_403',
     '{"all":[{"field":"extra.path","op":"contains","value":"/admin"}]}',
     'SOURCE_IP', 600, 20, 'LOW', 1800, 'T1595', TRUE);
