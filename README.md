# 경보기 SIEM — 5. 보안 위협 탐지 및 경보 관리

WBS 5 (기능정의서 No 117–152) 구현. 기준 문서는 다음과 같습니다.
- `경보기_테이블명세서.xlsx` v0.1: DB 구조는 이 문서에서 벗어나지 않습니다.
- 기능정의서 2차
- 목업 `Rules.html` · `Alerts.html`

기준 문서(엑셀 3개)와 DB 덤프는 팀 내부 자료라 저장소에 올리지 않습니다. 팀원에게 **`경보기_SIEM_팀문서_*.zip`** 을 따로 받으십시오.

```
run.py              실행 진입점 (python run.py)
frontend/           React 18 · Vite 화면 (목업 Rules · Alerts)
alarm/              Flask API · Python 3.12 · psycopg 3 · PostgreSQL 16
  rules.py          5.1 탐지 규칙 관리
  detect.py         5.2 탐지 엔진 (백그라운드 스레드, 10초 주기)
  threats.py        5.3 탐지 결과
  alerts.py         5.4 경보 관리
  events.py         normalized_event · raw_log 조회
  api.py            JSON API (/api/**)
  dev.py            개발용 테스트 API (/api/dev/**)
db/                 DDL · 초기 데이터
```

## 실행 방법

### 준비물
- **PostgreSQL 16**
- **Python 3.12** (3.10 이상)
- **Node.js 18 이상** (화면 빌드 · 개발 서버)

### 1. DB 생성 (최초 1회)
`db` 폴더의 파일을 순서대로 실행합니다.
1. `create-database.sql`: `postgres` 계정으로 실행합니다. `siem` 계정과 `siem` DB를 만듭니다.
2. `schema.sql`: `siem` 계정으로 실행합니다. 명세서의 26개 테이블, 월 파티션, 권한을 만듭니다.
3. `data.sql`: `siem` 계정으로 실행합니다. 코드와 설정 초기값, 기본 탐지 규칙을 넣습니다.

```powershell
$env:PGCLIENTENCODING = 'UTF8'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U siem -h localhost -d siem -v ON_ERROR_STOP=1 -f 'db\schema.sql'
```

### 2. 패키지 설치 (최초 1회)
```powershell
python -m venv .venv; .venv\Scripts\pip install -r requirements.txt
```
```powershell
cd frontend; npm install; npm run build; cd ..
```

### 3. 실행
환경변수 `DB_PASSWORD`에 `siem` 계정의 비밀번호를 넣고 실행합니다.
```powershell
$env:DB_PASSWORD = '비밀번호'; .venv\Scripts\python run.py
```
http://localhost:8080 을 엽니다. Flask가 API(`/api/**`)와 React 빌드 결과(`frontend/dist`)를 함께 내보냅니다.

**화면을 고치면서 개발할 때**는 Flask를 켜 둔 채로 React 개발 서버를 따로 띄웁니다. 저장하면 화면이 바로 바뀌고, `/api` 요청은 8080으로 전달됩니다.
```powershell
cd frontend; npm run dev
```
→ http://localhost:5173

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `DB_PASSWORD` | (없음) | `siem` 계정 비밀번호 |
| `DB_HOST` · `DB_PORT` · `DB_NAME` · `DB_USERNAME` | `localhost` · `5432` · `siem` · `siem` | DB 접속 정보 |
| `APP_PROFILE` | `dev` | `dev`면 테스트용 API `/api/dev/**`가 켜집니다. 운영은 `prod` |
| `PORT` · `HOST` | `8080` · (없음) | 서버 포트 · 주소. `HOST`가 없으면 `localhost`(IPv4 · IPv6 둘 다)에서 받습니다 |
| `DETECTION_INTERVAL_SEC` | `10` | 탐지 엔진 실행 주기(초) |
| `DETECTION_ENABLED` | `true` | `false`면 탐지 엔진을 자동 실행하지 않습니다 |
| `FLASK_DEBUG` | (없음) | `1`이면 Flask 개발 서버로 실행해 코드 수정 시 자동 재시작. 이때는 http://127.0.0.1:8080 으로 접속 |

`run.py`는 WSGI 서버 waitress로 실행합니다. Flask 개발 서버는 IPv4만 받아서, Windows 브라우저로 `localhost`에 접속하면 요청마다 약 0.3초씩 늦어집니다(IPv6 접속 실패 후 재시도). 서버는 **프로세스 1개**로만 띄웁니다(탐지 엔진의 처리 위치가 메모리에 있기 때문).

### 4. 동작 확인
`requests.http`에서 실행합니다.
1. `POST /api/dev/simulate/ssh-bruteforce`
2. 10초 안에 **위협 탐지 규칙 > 탐지 결과 탭**과 **경보 관리**에 새 항목이 생기는지 확인합니다.

시나리오는 `ssh-bruteforce`, `sudo-root`, `offhours-login`, `user-created`, `web-admin-scan`이 있습니다.

## 구조 (기능-테이블 매핑 시트 기준)

| WBS | 모듈 | 쓰는 테이블 (C 생성 / R 조회 / U 수정) |
|---|---|---|
| 5.1 탐지 규칙 관리 | `rules.py` | C detection_rule · admin_audit_log / R · U · 논리 D detection_rule |
| 5.2 탐지 실행 | `detect.py` · `events.py` | C threat_event · threat_event_link / R detection_rule · normalized_event / U normalized_event(severity) |
| 5.3 탐지 결과 | `threats.py` | R threat_event · threat_event_link · normalized_event · raw_log |
| 5.4 경보 관리 | `alerts.py` | C alert · alert_history / R alert · alert_policy / U alert |

- 탐지 엔진은 10초마다 실행되고, 실행할 때마다 `service_status`의 `DETECTOR` heartbeat를 갱신합니다.
- ORM 없이 SQL로 직접 다룹니다. 파티션 테이블(`raw_log`, `normalized_event`)이 복합 PK이기 때문입니다.
- `threat_no`와 `alert_no`는 시퀀스 기반입니다. 형식은 `EVT-yyyyMMdd(KST)-0001`, `ALT-0001`입니다.
- 화면은 React가 그리고 모든 데이터는 `/api/**`로 주고받습니다. React 라우터 경로(`/rules`, `/alerts` 등)는 Flask가 `index.html`로 응답합니다.

### 화면 · API 경로
| 화면 | API |
|---|---|
| `/rules` 규칙 관리 · 탐지 결과 탭 | `/api/rules`, `/api/threats`, `/api/codes/log-types`, `/api/codes/event-types` |
| `/alerts` 경보 관리 | `/api/alerts`, `/api/alerts/summary`, `/api/alerts/{id}/status`, `/api/alerts/{id}/false-positive` |

### 탐지 조건 형식 (명세서 예시 형식)
```json
condition_expr: {"all":[{"field":"extra.USER","op":"eq","value":"root"}]}
exceptions:     {"source_ip":["192.0.2.0/28"],"user_account":["svc-scanner"]}
evidence:       {"cond":"≥10회/5분","observed":"318회/5분"}
```
- **field**: `normalized_event` 컬럼명(`event_type_code`, `source_ip`, `user_account`, `host_name`, `dest_port` 등) 또는 `extra.<키>`
- **op**: `eq`, `ne`, `contains`, `regex`, `in`(값은 배열), `between`·`not_between`(`"a-b"`), `hour_between`·`hour_not_between`
  - `hour_` 연산자는 `event_time` 전용입니다. KST 시각 기준이며, `"9-18"`은 09:00~17:59입니다.
  - `regex`는 Python 정규식 문법입니다.
- **group_by**: `SOURCE_IP`, `USER_ACCOUNT`(`계정@호스트`), `TARGET`

## 명세서에 없어서 정한 것 (확인 필요)
| 항목 | 내용 |
|---|---|
| `alert_policy` 초기값 | INFO는 `NONE`, 나머지 4개 등급은 `IMMEDIATE`입니다. 근거는 코드 정의 시트의 "INFO = 경보 대상 아님"입니다. |
| `event_type`, 기본 탐지 규칙 | 기능정의서 LO_02_01의 탐지 대상 5종을 기준으로 넣었습니다. WBS 2.7에서 확정되면 교체합니다. |
| 파티션 | 2026-10 ~ 2027-03만 만들었습니다. 이후 달의 자동 생성과 보관 기간이 지난 파티션 DROP은 WBS 2.6 담당입니다. |
| 탐지 처리 위치 | 저장할 테이블이 명세서에 없어 서버 메모리에 둡니다. 재시작하면 최근 60분(`detection.startup-lookback-min`)을 다시 읽고, 이미 탐지된 이벤트는 건너뜁니다. |
| 작업자 ID | 로그인 기능(WBS 3.2)이 아직 없어 `created_by`, `actor_id`, `user_id`가 NULL로 기록됩니다. `alarm/common.py`의 `current_user_id()`를 교체해야 합니다. |
| 임계값 기준 | 기능정의서 No 134와 WBS 5.2.2.1의 "초과"를 따라 **초과(>)** 로 구현했습니다. 목업은 "≥"입니다. |
