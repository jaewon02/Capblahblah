# 경보기 SIEM — 5. 보안 위협 탐지 및 경보 관리

WBS 5 (기능정의서 No 117–152) 구현. 기준 문서는 다음과 같습니다.
- `경보기_테이블명세서.xlsx` v0.1: DB 구조는 이 문서에서 벗어나지 않습니다.
- 기능정의서 2차
- 목업 `Rules.html` · `Alerts.html`

기준 문서(엑셀 3개)와 DB 덤프는 팀 내부 자료라 저장소에 올리지 않습니다. 팀원에게 **`경보기_SIEM_팀문서_*.zip`** 을 따로 받으십시오.

```
backend/   Spring Boot 3.3 · Java 17 · JPA/JDBC · PostgreSQL 16
frontend/  React 18 · Vite · react-router
```

## 실행 방법

### 준비물
- **PostgreSQL 16**
- **JDK 17**: `C:\Users\EZ\.jdks\jdk-17.0.21+9`
- **Maven 3.9**: `C:\Users\EZ\.m2\apache-maven-3.9.16`
- **Node.js 18 이상**

### 1. DB 생성 (최초 1회)
`backend/src/main/resources/db` 폴더의 파일을 순서대로 실행합니다.
1. `create-database.sql`: `postgres` 계정으로 실행합니다. `siem` 계정과 `siem` DB를 만듭니다.
2. `schema.sql`: `siem` 계정으로 실행합니다. 명세서의 26개 테이블, 월 파티션, 권한을 만듭니다.
3. `data.sql`: `siem` 계정으로 실행합니다. 코드와 설정 초기값, 기본 탐지 규칙을 넣습니다.

```powershell
$env:PGCLIENTENCODING = 'UTF8'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U siem -h localhost -d siem -v ON_ERROR_STOP=1 -f 'backend\src\main\resources\db\schema.sql'
```

### 2. 백엔드
환경변수 `DB_PASSWORD`에 `siem` 계정의 비밀번호를 넣고 실행합니다.
- 기본 프로필은 `dev`입니다. 테스트용 API `/api/dev/**`가 켜집니다.
- 운영에서는 `--spring.profiles.active=prod`로 실행합니다.

```powershell
$env:DB_PASSWORD = '비밀번호'; cd backend; mvn spring-boot:run
```

### 3. 프론트
```powershell
cd frontend; npm install; npm run dev
```
http://localhost:5173 을 엽니다. `/api` 요청은 8080으로 전달됩니다.

### 4. 동작 확인
`backend/requests.http`에서 실행합니다.
1. `POST /api/dev/simulate/ssh-bruteforce`
2. 10초 안에 **탐지 결과 탭**과 **경보 관리**에 새 항목이 생기는지 확인합니다.

시나리오는 `ssh-bruteforce`, `sudo-root`, `offhours-login`, `user-created`, `web-admin-scan`이 있습니다.

## 구조 (기능-테이블 매핑 시트 기준)

| WBS | 백엔드 | 쓰는 테이블 (C 생성 / R 조회 / U 수정) |
|---|---|---|
| 5.1 탐지 규칙 관리 | `rule/` `DetectionRuleService` | C detection_rule · admin_audit_log / R · U · 논리 D detection_rule |
| 5.2 탐지 실행 | `detect/` `DetectionEngine` · `DetectionRunner` | C threat_event · threat_event_link / R detection_rule · normalized_event / U normalized_event(severity) |
| 5.3 탐지 결과 | `threat/` `ThreatService` | R threat_event · threat_event_link · normalized_event · raw_log |
| 5.4 경보 관리 | `alert/` `AlertService` | C alert · alert_history / R alert · alert_policy / U alert |

- 탐지 엔진은 10초마다 실행되고, 실행할 때마다 `service_status`의 `DETECTOR` heartbeat를 갱신합니다.
- 파티션 테이블(`raw_log`, `normalized_event`)은 복합 PK라서 JDBC로 직접 다룹니다(`NormalizedEventDao`).
- `threat_no`와 `alert_no`는 시퀀스 기반입니다. 형식은 `EVT-yyyyMMdd(KST)-0001`, `ALT-0001`입니다.

### 탐지 조건 형식 (명세서 예시 형식)
```json
condition_expr: {"all":[{"field":"extra.USER","op":"eq","value":"root"}]}
exceptions:     {"source_ip":["192.0.2.0/28"],"user_account":["svc-scanner"]}
evidence:       {"cond":"≥10회/5분","observed":"318회/5분"}
```
- **field**: `normalized_event` 컬럼명(`event_type_code`, `source_ip`, `user_account`, `host_name`, `dest_port` 등) 또는 `extra.<키>`
- **op**: `eq`, `ne`, `contains`, `regex`, `in`(값은 배열), `between`·`not_between`(`"a-b"`), `hour_between`·`hour_not_between`
  - `hour_` 연산자는 `event_time` 전용입니다. KST 시각 기준이며, `"9-18"`은 09:00~17:59입니다.
- **group_by**: `SOURCE_IP`, `USER_ACCOUNT`(`계정@호스트`), `TARGET`

## 명세서에 없어서 정한 것 (확인 필요)
| 항목 | 내용 |
|---|---|
| `alert_policy` 초기값 | INFO는 `NONE`, 나머지 4개 등급은 `IMMEDIATE`입니다. 근거는 코드 정의 시트의 "INFO = 경보 대상 아님"입니다. |
| `event_type`, 기본 탐지 규칙 | 기능정의서 LO_02_01의 탐지 대상 5종을 기준으로 넣었습니다. WBS 2.7에서 확정되면 교체합니다. |
| 파티션 | 2026-10 ~ 2027-03만 만들었습니다. 이후 달의 자동 생성과 보관 기간이 지난 파티션 DROP은 WBS 2.6 담당입니다. |
| 탐지 처리 위치 | 저장할 테이블이 명세서에 없어 서버 메모리에 둡니다. 재시작하면 최근 60분(`detection.startup-lookback-min`)을 다시 읽고, 이미 탐지된 이벤트는 건너뜁니다. |
| 작업자 ID | 로그인 기능(WBS 3.2)이 아직 없어 `created_by`, `actor_id`, `user_id`가 NULL로 기록됩니다. `CurrentUser`를 교체해야 합니다. |
| 임계값 기준 | 기능정의서는 "초과", 목업은 "≥"입니다. 현재는 목업대로 **이상(≥)** 으로 구현했습니다. |
