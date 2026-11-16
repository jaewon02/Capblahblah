# 경보기 SIEM 더미 데이터 — 기능정의서 238개 기능 테스트용

기준 문서: 테이블 명세서 v0.1 (26개 테이블), 기능정의서 2차 (No 1–238)
덤프 파일: `siem_dummy_20261116.sql` (PostgreSQL 16, 약 2.7MB)

## 1. 받아서 내 DB에 넣기

PostgreSQL 16이 설치된 PC에서, `siem` 계정과 `siem` DB가 없다면 먼저 만듭니다(`db/create-database.sql`, postgres 계정).
**`siem` DB가 비어 있어야 합니다.** 이미 테이블이 있으면 아래 0단계로 지운 뒤 넣습니다.

```powershell
# 0. (기존 테이블이 있을 때만) 전부 삭제
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U siem -h localhost -d siem -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
```
```powershell
# 1. 덤프 넣기 (siem 비밀번호 입력)
$env:PGCLIENTENCODING = 'UTF8'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U siem -h localhost -d siem -v ON_ERROR_STOP=1 -f siem_dummy_20261116.sql
```
```powershell
# 2. 확인: 26이 나오면 정상
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U siem -h localhost -d siem -tAc "select count(*) from pg_tables where schemaname='public' and tablename not like '%\_20%'"
```

> `DROP SCHEMA` 는 siem DB의 모든 데이터를 지웁니다. 내 테스트 데이터가 필요하면 먼저 백업하십시오.

## 2. 데이터 개요

- **기간**: 2026-11-03 00:00 ~ 2026-11-16 16:00 (KST, 14일). 데이터 속 '현재'는 **2026-11-16 16:00** 입니다.
  대시보드의 1시간 / 24시간 / 7일 조회는 실제 오늘 날짜 기준이면 비어 보일 수 있으니, 개발 중에는 기준 시각을 이 값으로 두고 시험하십시오.
- **위협 이벤트 · 근거 로그 연결 · 경보**는 직접 넣지 않고 **실제 탐지 엔진**(`alarm/detect.py`)을 돌려 만들었습니다. 탐지 로직과 데이터가 어긋나지 않습니다.
- 모든 IP는 문서 예시용 대역(192.0.2.x · 198.51.100.x · 203.0.113.x)과 사설 대역(10.x)입니다. 실존 개인정보는 없습니다.

| 테이블 | 건수 | 테이블 | 건수 |
|---|---:|---|---:|
| admin_user | 6 | detection_rule | 8 |
| admin_session | 34 | threat_event | 19 |
| login_history | 89 | threat_event_link | 380 |
| admin_audit_log | 32 | severity_override | 4 |
| log_type | 4 | incident | 3 |
| collect_target | 9 | alert | 19 |
| upload_file | 3 | alert_history | 81 |
| collect_job | 86 | alert_policy | 5 |
| raw_log | 3,311 | user_preference | 3 |
| parse_rule | 11 | stat_event_hourly | 1,082 |
| event_type | 15 | report | 6 |
| parse_result | 3,312 | system_setting | 8 |
| normalized_event | 3,259 | service_status | 5 |

## 3. 테스트 계정 (로그인 · 인증, No 1–24)

모든 계정의 비밀번호: **`Siem!Test2026`** (bcrypt 해시로 저장, 테스트 전용)

| login_id | 역할 | 상태 | 시험할 수 있는 것 |
|---|---|---|---|
| `admin` | ADMIN | 정상 | 설정 변경 · 재정의 승인 |
| `analyst01` | ANALYST | 정상 | 경보 처리 · 재정의 요청 |
| `analyst02` | ANALYST | 정상 (11-09 비밀번호 변경) | 비밀번호 변경 이력 |
| `viewer01` | VIEWER | 정상 | 조회 전용 권한 |
| `analyst03` | ANALYST | **잠김** (연속 5회 실패, 11-16 16:12 해제) | 로그인 제한 · 자동 해제 (No 6–8) |
| `olduser` | VIEWER | **비활성** (is_active = false) | 비활성 계정 로그인 차단 |

- `login_history`: 성공 · 실패(BAD_PASSWORD) · 없는 계정 시도(NO_USER, user_id NULL, 198.51.100.200) · 잠김 · 로그아웃 · 세션 만료
- `admin_session`: 사용 중(admin · analyst01) · 로그아웃(revoked_at) · 미사용 만료 세션

## 4. 기능별 테스트 데이터

| 기능 (No) | 데이터 |
|---|---|
| **수집 대상 관리** (26–36) | 9개: SYSLOG 5 (UDP · TCP · TLS), REST_API 1 (`api-gw`, cron 매일 02시), FILE_UPLOAD 1 (`legacy-ftp`), 수집 중지 1 (`test-vm`), **논리 삭제 1** (`old-mail`). 등록 · 수정 · 삭제 이력은 `admin_audit_log` |
| **자동 · 수동 수집** (37–44) | Syslog 일별 작업, REST 배치 (매일 02:00), 파일 업로드 3건. `duplicate_count` 로 중복 제외 건수 |
| **수집 오류** (45–49) | REST **FAIL** 3건 (HTTP 401, 11-07 · 11-13 · 11-16), REST **PARTIAL** 1건 (응답 시간 초과, 11-10), Syslog PARTIAL 1건 (was-02 TLS 인증서 만료, 11-09), 업로드 FAIL 1건 (인코딩 감지 실패, 11-14) |
| **수집 이력 · 검색** (50–54) | `collect_job` 86건 (오늘 것은 RUNNING) |
| **원본 로그 조회** (55–63) | 3,311건 · 대상 7곳 · 유형 4종 (인증 · 시스템 · 네트워크 · 웹) |
| **정규화 · 파싱** (64–85) | 정규화 3,259건. **파싱 실패 47건** (NO_MATCHING_RULE · TIME_FORMAT · MISSING_FIELD), **재시도 성공 6건** (attempt 1 FAIL → 2 SUCCESS), **파싱 대기(PENDING) 5건**. 파싱 규칙 11개 (카테고리 5종, 비활성 1개) |
| **이벤트 분석 · 연관** (87–96) | 같은 IP 반복 공격 (203.0.113.47: 11-05 · 11-16 / 198.51.100.230: 11-07 · 11-16 / 203.0.113.99: 포트 스캔 → 관리자 경로 탐색), 같은 계정 (deploy · kim). **3줄 요약** 3건 (`flow_summary`) |
| **위험 등급 · 재정의** (97–111) | 재정의 4건: **승인 2** (MEDIUM→LOW, HIGH→CRITICAL), **반려 1**, **대기 1**. 승인 건은 위협 이벤트 · 경보 · 정규화 이벤트 등급까지 반영 |
| **탐지 규칙 관리** (117–129) | 8개: 기본 6 + 사용자 등록 1 (`방화벽 포트 스캔`) + **논리 삭제 1**. **비활성 1** (감사 로그 규칙), **수정 v2 1** (SSH 규칙에 예외 조건 추가) |
| **탐지 실행 · 결과** (130–141) | 위협 이벤트 19건 (아래 시나리오). 임계값 미달 · 예외 조건 · 비활성 규칙으로 **탐지되지 않아야 하는 경우**도 포함 |
| **경보 관리** (142–152) | 경보 19건: 처리 완료 14 · 확인 2 · 미확인 3, **오탐 2**, 담당자 지정 · 코멘트 이력, 위험 등급 5종 중 4종 |
| **인시던트** [권장] | 3건: 같은 IP 반복 공격 · 권한 상승 연쇄 · 정찰 활동 |
| **대시보드** (153–186) | `stat_event_hourly` 1,082행 (완료된 시간대), 공격 유형 6종 (TOP 5용), 공격 IP 다수, 사용자 화면 설정 3명 (테마 · 기간 · 위젯) |
| **보고서** (187–212) | 6건: 일간 · 주간 · 월간, PDF · CSV, 완료 4 · 생성 중 1 · 실패 1. **실제 파일은 없음** (`file_path` 만 있음) |
| **시스템 설정** (213–238) | 설정값 8개 (변경 이력 2), 경보 정책 (LOW = 1시간 3건 누적, INFO = 미생성), 서비스 상태 5개 (API 수집기 DEGRADED), 관리자 작업 이력 32건 (CREATE · UPDATE · DELETE · APPROVE · REJECT · LOCK · PASSWORD_CHANGE) |

## 5. 탐지 시나리오 (위협 이벤트 19건)

| 날짜 (KST) | 규칙 | 대상 | 결과 |
|---|---|---|---|
| 11-04 02:13 | 운영 시간 외 로그인 | kim@bastion | 탐지 → 처리 완료 |
| 11-05 03:14 | SSH 반복 인증 실패 | 203.0.113.47 (60회) | 탐지 → INC-0001 |
| 11-06 14:12 · 14:15 | sudo root 셸 → 계정 생성 | deploy@db-01 → db-01 | 탐지 2건 → INC-0002 (종료) |
| 11-07 11:00 | SSH 반복 인증 실패 | 198.51.100.12 (8회) | **임계값 미달 → 미탐지** |
| 11-07 21:06 | 웹 관리자 경로 403 | 198.51.100.230 (45회) | 탐지 |
| 11-08 23:40 | 운영 시간 외 로그인 | ops@bastion | 탐지 → **오탐** · 등급 LOW로 재정의 승인 |
| 11-09 14:41 | SSH 반복 인증 실패 | 198.51.100.77 | 탐지 |
| 11-10 11:20 · 11:25 | sudo root 셸 · 그룹 변경 | park@was-02 | 탐지 2건, sudo 건 CRITICAL로 재정의 승인 |
| 11-10 11:30 | 감사 서비스 중지 | was-02 | **규칙 비활성 → 미탐지** |
| 11-11 06:30 | 운영 시간 외 로그인 | deploy@bastion | 탐지 |
| 11-12 03:20 · 03:34 | 포트 스캔 → 관리자 경로 403 | 203.0.113.99 | 탐지 2건 → INC-0003 |
| 11-12 22:05 | SSH 반복 인증 실패 | 192.0.2.10 (15분 지속) | 탐지 1건 (나머지는 중복 억제) |
| 11-13 09:30 | 계정 삭제 | db-01 | 탐지 → **오탐** (재정의 요청은 반려) |
| 11-14 10:00 | SSH 반복 인증 실패 | 10.0.0.50 svc-scanner | **예외 조건 → 미탐지** |
| 11-15 01:05 | 운영 시간 외 로그인 | kim@bastion | 탐지 → 확인 |
| 11-15 16:45 | sudo root 셸 | deploy@db-01 | 탐지 → 확인 |
| 11-16 13:40 | 계정 생성 | db-01 | 탐지 → 미확인 |
| 11-16 14:06 | 웹 관리자 경로 403 | 198.51.100.230 | 탐지 → 미확인, 등급 재정의 **대기** |
| 11-16 15:31 | SSH 반복 인증 실패 | 203.0.113.47 (같은 IP 재공격) | 탐지 → 미확인, INC-0001 |

## 6. 주의 · 알려진 사항

- **명세서 오류**: `incident.status` 는 `VARCHAR(10)` 인데 명세서 값 `INVESTIGATING` 은 13자라 들어가지 않습니다. 더미 데이터는 `OPEN` · `CLOSED` 만 씁니다. DB 담당 확인이 필요합니다.
- `event_type` 에 공격 유형 · ATT&CK · 기본 등급을 채우고 6개 유형을 추가했습니다 (WBS 2.7 코드 정의서 확정 시 교체).
- `threat_no` 의 뒷자리는 위협 이벤트 ID라 날짜 순서와 다를 수 있습니다.
- 탐지 엔진은 처리 위치를 메모리에 둡니다. 덤프를 넣은 뒤 서버를 켜도 과거 이벤트를 다시 탐지하지 않습니다 (이미 연결된 이벤트는 건너뜀).

## 7. 다시 만들기

`generate_dummy.py` 로 같은 데이터를 다시 만들 수 있습니다 (시드 고정). `schema.sql` · `data.sql` 만 적용한 빈 DB에서 실행합니다.
```powershell
.venv\Scripts\pip install bcrypt
$env:DB_PASSWORD = '비밀번호'; .venv\Scripts\python db\dummy\generate_dummy.py
& 'C:\Program Files\PostgreSQL\16\bin\pg_dump.exe' -U siem -h localhost -d siem --no-owner --encoding=UTF8 -f siem_dummy_20261116.sql
```
