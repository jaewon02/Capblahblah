import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, notifyAlertsChanged } from '../api.js';
import { ALERT_STATUS, SEVERITIES, formatTime, severityLabel } from '../format.js';
import { ErrorBox, SeverityBadge } from '../components/common.jsx';

const PAGE_SIZE = 50;

// 상태 칩 → 검색 조건
const CHIPS = [
  { key: 'all', label: '전체', count: (s) => s.total, params: {} },
  { key: 'NEW', label: '미확인', count: (s) => s.newCount, params: { status: 'NEW' } },
  { key: 'ACK', label: '확인', count: (s) => s.ackCount, params: { status: 'ACK' } },
  { key: 'RESOLVED', label: '처리 완료', count: (s) => s.resolvedCount, params: { status: 'RESOLVED' } },
  { key: 'fp', label: '오탐', count: (s) => s.falsePositiveCount, params: { falsePositive: true } },
];

const EMPTY_FILTER = { severity: '', from: '', to: '' };

/** 경보 관리 (목업 Alerts.html · No 142–152) */
export default function AlertsPage() {
  const [chip, setChip] = useState('all');
  const [input, setInput] = useState(EMPTY_FILTER);   // 입력 중인 검색 조건
  const [filter, setFilter] = useState(EMPTY_FILTER); // [검색]으로 적용된 조건
  const [page, setPage] = useState(0);
  const [data, setData] = useState({ content: [], totalElements: 0 });
  const [summary, setSummary] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(() => {
    const chipParams = CHIPS.find((c) => c.key === chip).params;
    Promise.all([
      api.alerts({ ...filter, ...chipParams, page, size: PAGE_SIZE }),
      api.alertSummary(filter),
    ])
      .then(([list, sum]) => {
        setData(list);
        setSummary(sum);
      })
      .catch((e) => setError(e.message));
  }, [chip, filter, page]);

  useEffect(load, [load]);

  const search = (e) => {
    e.preventDefault();
    if (input.from && input.to && input.from > input.to) {
      setError('시작일이 종료일보다 늦습니다.');
      return;
    }
    setError(null);
    setPage(0);
    setFilter(input);
  };

  const reset = () => {
    setInput(EMPTY_FILTER);
    setFilter(EMPTY_FILTER);
    setPage(0);
  };

  const run = async (id, action) => {
    setError(null);
    setBusyId(id);
    try {
      await action();
      load();
      notifyAlertsChanged();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  };

  const nextStatus = (a) => run(a.alertId, () => api.changeAlertStatus(a.alertId, ALERT_STATUS[a.status].next));

  const toggleFalsePositive = (a) => {
    let comment = null;
    if (!a.falsePositive) {
      comment = window.prompt(`${a.alertNo}을(를) 오탐으로 지정합니다. 사유를 입력하세요 (선택).`, '');
      if (comment === null) return; // 취소
    }
    run(a.alertId, () => api.setFalsePositive(a.alertId, !a.falsePositive, comment));
  };

  const totalPages = Math.max(1, Math.ceil(data.totalElements / PAGE_SIZE));

  return (
    <>
      <header className="page-head">
        <div>
          <h1>경보 관리</h1>
          <div className="muted sub">탐지 즉시 경보 생성 · 미확인 → 확인 → 처리 완료 · 오탐 지정</div>
        </div>
      </header>

      <div className="toolbar">
        <div className="row" role="group" aria-label="상태 필터">
          {CHIPS.map((c) => (
            <button key={c.key} type="button" className={`chip ${chip === c.key ? 'on' : ''}`}
              aria-pressed={chip === c.key}
              onClick={() => { setChip(c.key); setPage(0); }}>
              {c.label} <span style={{ fontWeight: 600 }}>{summary ? c.count(summary) : '-'}</span>
            </button>
          ))}
        </div>
        <form className="row" onSubmit={search} aria-label="경보 검색">
          <div className="field" style={{ width: 140 }}>
            <label htmlFor="lg">위험 등급</label>
            <select id="lg" value={input.severity} onChange={(e) => setInput({ ...input, severity: e.target.value })}>
              <option value="">전체</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{severityLabel(s)}</option>)}
            </select>
          </div>
          <div className="field" style={{ width: 150 }}>
            <label htmlFor="ls">시작일</label>
            <input id="ls" type="date" value={input.from} onChange={(e) => setInput({ ...input, from: e.target.value })} />
          </div>
          <div className="field" style={{ width: 150 }}>
            <label htmlFor="le">종료일</label>
            <input id="le" type="date" value={input.to} onChange={(e) => setInput({ ...input, to: e.target.value })} />
          </div>
          <button type="submit" className="btn pri">검색</button>
          <button type="button" className="btn" onClick={reset}>초기화</button>
        </form>
      </div>

      <ErrorBox error={error} />

      <div className="card flush">
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>경보 ID</th><th>발생 시각</th><th>위험 등급</th><th>탐지 내용</th><th>상태</th><th>오탐</th>
                <th><span className="sr-only">처리</span></th>
              </tr>
            </thead>
            <tbody>
              {data.content.length === 0 && (
                <tr><td colSpan={7} className="empty">조건에 맞는 경보가 없습니다.</td></tr>
              )}
              {data.content.map((a) => {
                const st = ALERT_STATUS[a.status];
                const busy = busyId === a.alertId;
                return (
                  <tr key={a.alertId} className={a.falsePositive ? 'fp' : ''}>
                    <td className="mono">{a.alertNo}</td>
                    <td className="mono">{formatTime(a.createdAt)}</td>
                    <td><SeverityBadge value={a.severity} /></td>
                    <td style={{ whiteSpace: 'normal', minWidth: 260 }}>
                      <div>{a.title}</div>
                      <div className="muted" style={{ fontSize: 12 }}>
                        규칙: <Link to="/rules">{a.ruleName ?? '(삭제된 규칙)'}</Link>
                      </div>
                    </td>
                    <td><span className={`b ${st.cls}`}>{st.label}</span></td>
                    <td>{a.falsePositive && <span className="b info">오탐</span>}</td>
                    <td style={{ textAlign: 'right' }}>
                      {st.next && (
                        <>
                          <button type="button" className="btn sm" disabled={busy} onClick={() => nextStatus(a)}>
                            {st.nextLabel}
                          </button>{' '}
                        </>
                      )}
                      <button type="button" className="btn sm" disabled={busy} onClick={() => toggleFalsePositive(a)}>
                        {a.falsePositive ? '오탐 해제' : '오탐 지정'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {data.totalElements > PAGE_SIZE && (
        <div className="row" style={{ justifyContent: 'center', alignItems: 'center' }}>
          <button type="button" className="btn sm" disabled={page === 0} onClick={() => setPage(page - 1)}>이전</button>
          <span className="muted">{page + 1} / {totalPages}</span>
          <button type="button" className="btn sm" disabled={page + 1 >= totalPages} onClick={() => setPage(page + 1)}>다음</button>
        </div>
      )}
    </>
  );
}
