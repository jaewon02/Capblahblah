# 경보기 SIEM 탐지·경보 — 구현 판단 사항 정리

2026-11-10

## 개요

WBS 5(보안 위협 탐지 및 경보 관리)를 구현하면서 기준 문서에 값이나 규칙이 없어 개발자가 판단해 정한 항목을 모았습니다. 팀 확인 후 확정하거나 수정하기 위한 문서입니다.

- 기준 문서: 경보기\_테이블명세서.xlsx v0.1(2026-10-29), 20261008\_경보기\_기능정의서\_2차.xlsx, 목업 Rules.html · Alerts.html
- DB 구조(테이블 26개, 컬럼 259개, PK · FK · NOT NULL · UNIQUE · 기본값 · CHECK · INDEX)는 명세서와 자동 대조 결과 불일치 0건으로, 이 문서의 판단 항목에 포함되지 않습니다.
- 아래 항목은 DB에 넣은 값, 탐지 로직, 번호 규칙, 화면 · API, 개발 환경에 관한 것입니다.

## 꼭 확인받아야 할 항목

기능 결과가 달라지는 4가지입니다. PM · 기획 · DB 담당 확인이 필요합니다.

| No | 항목 | 현재 구현 | 문서 상황 | 확인 대상 |
| --- | --- | --- | --- | --- |
| 1 | 임계값 판정 | 이상(≥) | 기능정의서 No 134는 "초과", 목업은 "≥" — 문서 간 충돌 | PM · 기획 |
| 2 | 경보 정책 초기값 | INFO만 NONE, 나머지 4개 등급 IMMEDIATE | 명세서는 "5행 고정"만 있고 값 없음. 코드 정의 "INFO = 경보 대상 아님(기본)"을 근거로 함 | PM · 기획 |
| 3 | 탐지 처리 위치 | 서버 메모리에 보관, 재시작 시 최근 60분 재확인(중복은 건너뜀) | 저장할 테이블 · 설정 키 없음. 서버가 60분 넘게 꺼져 있으면 그 사이 이벤트는 탐지되지 않음 | DB 담당 (예: system\_setting 키 추가) |
| 4 | threat\_no 번호 규칙 | EVT-날짜(KST)-전체 시퀀스 | 명세서 예시 EVT-20261020-0412만 있음. 뒷자리가 일별 순번인지 불명확 | DB · 기획 |

## DB 초기 데이터

테이블 구조는 명세서 그대로이고, 아래는 data.sql · schema.sql에 넣은 값 중 명세서에 없는 것입니다. log\_type 4개와 system\_setting 8개는 명세서 코드 정의 시트 값 그대로입니다.

| 항목 | 정한 값 | 근거 |
| --- | --- | --- |
| alert\_policy 5행 | CRITICAL · HIGH · MEDIUM · LOW = IMMEDIATE, INFO = NONE | 코드 정의 "INFO = 경보 대상 아님(기본)" |
| event\_type 9개 | ssh\_auth\_failed, ssh\_login\_success, sudo\_exec, user\_created, user\_deleted, usermod, auditd\_stopped, audit\_rule\_changed, http\_403 | 기능정의서 LO\_02\_01 탐지 대상 5종에 필요한 유형. attack\_type · default\_severity는 비움. WBS 2.7 확정 시 교체 |
| 기본 탐지 규칙 6개 | 탐지 대상 5종 + 웹 관리자 경로 403 반복 | 5종은 기능정의서, 403 규칙은 목업에만 있음. 감사 로그 규칙은 목업처럼 비활성 |
| 규칙 수치 | SSH 실패 5분 10회, 운영 시간 09\~18시, 웹 403 10분 20회 | 목업 값 |
| 규칙별 중복 억제(suppress\_sec) | SSH 600초, 운영 시간 외 3600초, 웹 403 1800초, 나머지 0 | 개발자 판단 |
| 규칙별 ATT&CK 기법 | T1110, T1078, T1548, T1136, T1562, T1595 | 개발자 판단 |
| 월 파티션 범위 | 2026-10 \~ 2027-03 (테이블 3개 × 6개월), 경계는 UTC 기준 | 범위 없음. 이후 자동 생성 · DROP은 WBS 2.6 |
| DB 계정 | siem 계정이 테이블 소유자, admin\_audit\_log는 siem에서 UPDATE · DELETE · TRUNCATE 회수 | 명세서는 "애플리케이션 계정에 권한 미부여"만 명시 |

## 탐지 로직

탐지 엔진(DetectionEngine)의 동작 중 문서에 없는 부분입니다. 조건 형식 {"all":\[...\]}과 예외 형식은 명세서 예시를 따랐습니다.

| 항목 | 정한 내용 |
| --- | --- |
| 임계값 판정 | 이상(≥). 기능정의서 "초과"와 목업 "≥"가 충돌해 목업을 따름 |
| 조건 연산자 | 명세서 예시는 eq 하나. ne, in(배열), contains, regex, between · not\_between("a-b"), hour\_between · hour\_not\_between 추가 |
| 운영 시간 판단 | event\_time 전용 hour\_ 연산자, KST 기준. "9-18" = 09:00\~17:59(18시 미포함) |
| 조건 필드 이름 | normalized\_event 컬럼명(event\_type\_code, source\_ip, user\_account, host\_name, dest\_port 등) + extra.<키> |
| 예외 조건 비교 | source\_ip · dest\_ip는 CIDR 대역 포함 비교, 그 외 필드는 완전 일치 |
| group\_key 값 | SOURCE\_IP = 출발지 IP, USER\_ACCOUNT = 계정@호스트, TARGET = 호스트명(없으면 target-ID). 명세서 예시 deploy@db-01을 보고 해석 |
| 그룹 기준 없는 조건 기반 규칙 | 호스트명, 없으면 출발지 IP를 그룹 키로 사용 |
| 대표값(source\_ip · user\_account · target\_id) | 근거 이벤트 중 마지막 이벤트의 값 |
| 근거 로그 연결 상한 | 위협 1건당 최근 500건까지 threat\_event\_link에 연결 |
| 처리 위치 | 서버 메모리. 재시작 시 최근 60분 재확인, 이미 탐지된 이벤트 · 그룹은 건너뜀 |
| 실행 주기 · 묶음 | 10초마다, 1,000건씩. 서버 1대 기준(여러 대면 분산 잠금 필요) |
| normalized\_event.severity | 기존 등급과 규칙 등급 중 높은 쪽을 남김 |
| 탐지 엔진 상태 | 실행마다 service\_status의 DETECTOR를 UP, 실패 시 DEGRADED로 갱신 |

## 번호 · 경보

경보 상태 값(NEW · ACK · RESOLVED)과 오탐 별도 플래그는 명세서 그대로이고, 아래는 형식과 동작 중 정해진 것이 없던 부분입니다.

| 항목 | 정한 내용 |
| --- | --- |
| threat\_no | EVT-날짜(KST yyyyMMdd)-threat\_id 4자리. 예: EVT-20261110-0001 |
| alert\_no | ALT-alert\_id 4자리. 예: ALT-0001 (명세서 "시퀀스 기반, 접미사 금지" 준수) |
| alert.title | 규칙명 — 그룹 키 (관측값). 예: SSH 반복 인증 실패 — 203.0.113.47 (15회 / 5분). 300자 초과 시 자름 |
| evidence 내용 | cond(조건 요약) · observed(관측값) 두 키만 저장. 명세서 예시 형식 |
| 경보 정책 THRESHOLD 동작 | 같은 등급 위협 이벤트가 threshold\_window\_sec 안에 threshold\_count건 이상이면 경보 생성 |
| 경보 상태 변경 | 한 단계씩만 진행, 되돌리기 · 건너뛰기 불가(409 오류) |
| 오탐 지정 이력 | alert\_history에 action=FALSE\_POSITIVE, from · to는 "false" · "true" 문자열, 사유는 comment |
| 자동 생성 이력 | 경보 생성 시 alert\_history에 STATUS(없음 → NEW) 1행, actor\_id는 NULL(시스템) |

## 화면 · API

화면 구성은 목업(Rules.html · Alerts.html)을 따랐고, 아래는 목업과 다르거나 목업에 없는 부분입니다.

| 항목 | 정한 내용 |
| --- | --- |
| 규칙 등록 폼 | 목업에 없는 추가 조건, 중복 억제(분), \[권장\] 예외 조건(출발지 IP · 계정), ATT&CK 기법 입력란 추가. 명세서 컬럼을 입력하기 위함 |
| 입력 길이 제한 | 규칙 이름 100자, 설명 500자, ATT&CK 20자, 오탐 사유 1000자. 명세서 컬럼 길이 기준 |
| 오탐 지정 | 사유 입력 창을 띄움(입력은 선택), 취소하면 지정 안 함 |
| 탐지 근거 화면 | 관련 로그 원문 최근 20건(목업은 3건) + 전체 연결 건수 표시 |
| 메뉴 배지 | 미확인(NEW)이면서 오탐이 아닌 경보 수. 30초마다 · 화면 이동 시 · 처리 직후 갱신 |
| 경보 검색 기간 | 날짜는 KST 기준, 종료일 당일 포함. 비우면 전체 기간 |
| 목록 크기 | 경보 50건씩 페이지, 탐지 결과 100건 |
| 다른 메뉴 6개 | "준비 중" 화면만 표시(다른 담당 영역) |
| API 경로 | /api/rules, /api/threats, /api/alerts, /api/alerts/summary, /api/codes. 오류는 {"message"} 형식 |
| 테스트 API | /api/dev/simulate/{시나리오}, /api/dev/detect. dev 프로필에서만 동작, 테스트용 수집 대상(bastion · db-01 · web-01)을 자동 생성 |

## 개발 환경

DBMS(PostgreSQL 16)는 명세서 개요에 명시된 값이고, 아래는 문서에 없어 정한 것입니다.

| 항목 | 정한 내용 |
| --- | --- |
| 기술 스택 | React 18 + Vite, Spring Boot 3.3 + Java 17 + Maven (React + Spring Boot는 담당자 선택) |
| 패키지명 | com.siem.alarm |
| DB 접근 방식 | 일반 테이블은 JPA, 파티션 테이블(복합 PK)과 위협 · 경보 생성은 JDBC |
| 프로필 | dev(기본, 테스트 API 켜짐) / prod. 로컬 내장 DB(H2)는 INET · JSONB · 파티션 미지원으로 제거 |
| 작업자 ID | 로그인(WBS 3.2) 연동 전이라 created\_by · updated\_by · actor\_id · admin\_audit\_log.user\_id가 NULL로 기록됨. CurrentUser 교체 필요 |
| 가정 · 이슈 #3 · #5 | 명세서 설계대로 상태 · 오탐 분리, 위험 등급 원천은 threat\_event.severity |
| DB 비밀번호 | 로컬 개발용 siem 계정 비밀번호가 create-database.sql에 평문으로 들어 있음. 다른 환경에서는 변경 필요 |
