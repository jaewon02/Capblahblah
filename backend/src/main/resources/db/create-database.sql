-- 최초 1회: postgres(관리자) 계정으로 실행
-- 애플리케이션 전용 계정 siem 과 데이터베이스 siem 을 만든다.
-- 'change-me' 는 원하는 비밀번호로 바꿔서 실행하고, 같은 값을 DB_PASSWORD 환경변수로 설정한다.

CREATE ROLE siem LOGIN PASSWORD 'change-me';
CREATE DATABASE siem OWNER siem ENCODING 'UTF8' TEMPLATE template0;
