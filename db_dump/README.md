# 경보기 SIEM DB 덤프 — 다른 PC에서 DB 만들기

덤프 파일은 팀 내부 자료라 저장소에 올리지 않습니다. 팀원에게 **`경보기_SIEM_팀문서_*.zip`** 을 받아 `DB덤프` 폴더의 파일을 이 폴더(`db_dump`)에 넣고 진행하십시오.

| 파일 | 내용 |
|---|---|
| `create-database.sql` | `siem` 계정과 `siem` DB 생성 (postgres 계정으로 1회 실행) |
| `siem_20261110.sql` | 테이블 명세서 v0.1 기준 26개 테이블 · 월 파티션(2026-10 ~ 2027-03) · 인덱스 · 제약조건 · 권한 + 초기 데이터 |

- 덤프 원본: PostgreSQL 16.15, `pg_dump --no-owner`, 인코딩 UTF-8
- 초기 데이터: 로그 유형 4 · 이벤트 유형 9 · system_setting 8 · alert_policy 5 · 탐지 규칙 6 (테스트 데이터 없음)
- 덤프 파일 없이 DB를 만들려면 `backend/src/main/resources/db` 의 `create-database.sql` → `schema.sql` → `data.sql` 을 순서대로 실행해도 같은 결과입니다.

## 복원 순서 (PostgreSQL 16 설치된 PC)

PowerShell에서 `db_dump` 폴더로 이동한 뒤 실행합니다.

**1. 계정 · DB 생성** — `create-database.sql` 의 비밀번호(`'change-me'`)를 원하는 값으로 바꾼 뒤, `postgres` 비밀번호 입력

```powershell
$env:PGCLIENTENCODING = 'UTF8'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -h localhost -f create-database.sql
```

**2. 덤프 복원** — `siem` 비밀번호 입력

```powershell
$env:PGCLIENTENCODING = 'UTF8'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U siem -h localhost -d siem -v ON_ERROR_STOP=1 -f siem_20261110.sql
```

**3. 확인** — 테이블 26개가 나오면 정상

```powershell
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U siem -h localhost -d siem -c "\dt"
```

## 주의
- 2단계는 **빈 DB**에 실행해야 합니다. 이미 테이블이 있으면 오류가 납니다.
- 계정 이름은 반드시 `siem` 이어야 합니다. 덤프 안의 권한 설정(`admin_audit_log` INSERT 전용)이 `siem` 계정을 대상으로 합니다.
- 다른 버전(15 이하)의 PostgreSQL에서는 일부 구문이 실패할 수 있습니다. 명세서 기준 DBMS는 PostgreSQL 16입니다.
- 2027-04 이후 데이터를 넣으려면 해당 월 파티션을 먼저 만들어야 합니다 (WBS 2.6 보관 정책 담당).
