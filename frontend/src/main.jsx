import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout.jsx';
import RulesPage from './pages/RulesPage.jsx';
import AlertsPage from './pages/AlertsPage.jsx';
import Placeholder from './pages/Placeholder.jsx';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Navigate to="/rules" replace />} />
          {/* 5. 보안 위협 탐지 및 경보 관리 */}
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          {/* 다른 담당 영역 — 각 담당자가 화면 추가 */}
          <Route path="/dashboard" element={<Placeholder title="대시보드" wbs="3.10" />} />
          <Route path="/collect" element={<Placeholder title="로그 수집 관리" wbs="3.3" />} />
          <Route path="/logs" element={<Placeholder title="로그 조회 · 파싱" wbs="3.4 · 3.5" />} />
          <Route path="/analysis" element={<Placeholder title="로그 분석 · 위험 등급" wbs="3.7" />} />
          <Route path="/reports" element={<Placeholder title="보고서" wbs="3.11" />} />
          <Route path="/settings" element={<Placeholder title="시스템 설정" wbs="3.9" />} />
          <Route path="*" element={<Navigate to="/rules" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
);
