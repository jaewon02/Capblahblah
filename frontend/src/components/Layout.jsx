import { NavLink, Outlet } from 'react-router-dom';

// 미확인 경보 배지는 대시보드 기능(No 180–181, WBS 3.10)이라 메뉴에는 두지 않는다
const MENU = [
  { to: '/dashboard', label: '대시보드' },
  { to: '/collect', label: '로그 수집 관리' },
  { to: '/logs', label: '로그 조회 · 파싱' },
  { to: '/analysis', label: '로그 분석 · 위험 등급' },
  { to: '/rules', label: '위협 탐지 규칙' },
  { to: '/alerts', label: '경보 관리' },
  { to: '/reports', label: '보고서' },
  { to: '/settings', label: '시스템 설정' },
];

export default function Layout() {
  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">
          <div className="brand-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" strokeWidth="2"
              strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
              <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
            </svg>
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 16 }}>경보기</div>
            <div className="muted" style={{ fontSize: 12 }}>SIEM 관리자</div>
          </div>
        </div>
        <nav className="nav" aria-label="주 메뉴">
          {MENU.map((m) => (
            <NavLink key={m.to} to={m.to} className={({ isActive }) => (isActive ? 'on' : '')}>
              {m.label}
            </NavLink>
          ))}
        </nav>
        <div className="side-foot">
          {/* TODO: WBS 3.2 로그인 · 세션 연동 */}
          <div style={{ fontSize: 13, fontWeight: 600 }}>admin</div>
          <div className="muted" style={{ fontSize: 12 }}>세션 만료까지 [MM:SS]</div>
          <a href="#" style={{ fontSize: 13 }}>로그아웃</a>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}
