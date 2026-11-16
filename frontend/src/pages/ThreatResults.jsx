import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import { ALERT_STATUS, formatTime } from '../format.js';
import { ErrorBox, SeverityBadge } from '../components/common.jsx';

/** 탐지 결과 탭: 탐지된 위협 목록(No 139) + 탐지 근거 · 관련 로그(No 141) */
export default function ThreatResults() {
  const [items, setItems] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(() => {
    api
      .threats({ size: 100 })
      .then((page) => {
        setItems(page.content);
        setSelectedId((cur) => cur ?? page.content[0]?.threatId ?? null);
      })
      .catch((e) => setError(e.message));
  }, []);

  useEffect(load, [load]);

  useEffect(() => {
    if (selectedId == null) {
      setDetail(null);
      return;
    }
    let alive = true;
    api.threat(selectedId).then((d) => alive && setDetail(d)).catch((e) => alive && setError(e.message));
    return () => {
      alive = false;
    };
  }, [selectedId]);

  return (
    <>
      <ErrorBox error={error} />
      <div className="split">
        <div className="card flush grow">
          <div className="scroll">
            <table>
              <thead>
                <tr><th>탐지 시각</th><th>규칙</th><th>대상</th><th>위험 등급</th></tr>
              </thead>
              <tbody>
                {items.length === 0 && (
                  <tr><td colSpan={4} className="empty">탐지된 위협이 없습니다.</td></tr>
                )}
                {items.map((t) => (
                  <tr key={t.threatId} className={`click ${t.threatId === selectedId ? 'sel' : ''}`} onClick={() => setSelectedId(t.threatId)}>
                    <td className="mono">{formatTime(t.detectedAt)}</td>
                    <td>{t.ruleName}</td>
                    <td className="mono">{t.groupKey ?? '-'}</td>
                    <td><SeverityBadge value={t.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card side-card stack" style={{ gap: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2 style={{ margin: 0 }}>탐지 근거</h2>
            <button type="button" className="btn sm" onClick={load}>새로 고침</button>
          </div>
          {detail ? <Evidence detail={detail} /> : <div className="muted">왼쪽 목록에서 위협을 선택하세요.</div>}
        </div>
      </div>
    </>
  );
}

function Evidence({ detail }) {
  const { threat, evidence, alert, logs, linkedLogCount, ruleVersion } = detail;
  return (
    <>
      <div className="kv">
        <span className="muted">규칙</span>
        <span>{threat.ruleName} <span className="muted">(v{ruleVersion} · {threat.threatNo})</span></span>
        <span className="muted">적용 조건</span>
        <span className="mono">{evidence?.cond ?? '-'}</span>
        <span className="muted">관측값</span>
        <span className="mono" style={{ color: '#FFB677' }}>{evidence?.observed ?? '-'}</span>
        <span className="muted">위험 등급</span>
        <span><SeverityBadge value={threat.severity} /></span>
        <span className="muted">경보</span>
        <span>
          {alert ? (
            <Link to="/alerts">
              {alert.alertNo} ({ALERT_STATUS[alert.status]?.label}{alert.falsePositive ? ' · 오탐' : ''})
            </Link>
          ) : (
            <span className="muted">생성 안 됨 (경보 정책)</span>
          )}
        </span>
      </div>
      <div className="field">
        <label>
          관련 로그 원문 (최근 {logs.length}건{linkedLogCount > logs.length ? ` / 전체 ${linkedLogCount}건` : ''})
        </label>
        <pre className="code">{logs.map((l) => l.raw).join('\n') || '연결된 로그가 없습니다.'}</pre>
      </div>
    </>
  );
}
