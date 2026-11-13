"""실행: python run.py  →  http://localhost:8080

환경변수: DB_PASSWORD(필수), DB_HOST, DB_PORT, DB_NAME, DB_USERNAME, APP_PROFILE(dev|prod), PORT, HOST, FLASK_DEBUG
"""
import os

from alarm import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    if os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true"):
        # 코드 수정 시 자동 재시작 (개발용). IPv4만 받으므로 http://127.0.0.1:8080 으로 접속
        app.run(host=os.environ.get("HOST", "127.0.0.1"), port=port, debug=True)
    else:
        from waitress import serve

        # localhost 를 IPv4 · IPv6 둘 다 받는다. 한쪽만 받으면 Windows 브라우저가 IPv6(::1)로 먼저
        # 접속을 시도했다가 실패한 뒤 IPv4로 다시 접속해 요청마다 약 0.3초씩 늦어진다.
        host = os.environ.get("HOST")
        listen = f"{host}:{port}" if host else f"127.0.0.1:{port} [::1]:{port}"
        print(f"경보기 SIEM 실행 중: http://localhost:{port}  (종료: Ctrl+C)", flush=True)
        serve(app, listen=listen, threads=8)
