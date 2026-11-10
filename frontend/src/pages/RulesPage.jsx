import { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { METHOD_LABEL } from '../format.js';
import { ErrorBox, SeverityBadge, Switch } from '../components/common.jsx';
import RuleForm from './RuleForm.jsx';
import ThreatResults from './ThreatResults.jsx';

/** 위협 탐지 규칙 (목업 Rules.html) — 탭1: 규칙 관리(5.1), 탭2: 탐지 결과(5.3) */
export default function RulesPage() {
  const [tab, setTab] = useState('rules');
  const [rules, setRules] = useState([]);
  const [codes, setCodes] = useState({ logTypes: [], eventTypes: [] });
  const [editing, setEditing] = useState(null); // null = 신규 등록
  const [formKey, setFormKey] = useState(0);
  const [error, setError] = useState(null);

  const loadRules = useCallback(() => {
    api.rules().then(setRules).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    loadRules();
    Promise.all([api.logTypes(), api.eventTypes()])
      .then(([logTypes, eventTypes]) => setCodes({ logTypes, eventTypes }))
      .catch((e) => setError(e.message));
  }, [loadRules]);

  const startCreate = () => {
    setTab('rules');
    setEditing(null);
    setFormKey((k) => k + 1);
  };

  const startEdit = (rule) => {
    setEditing(rule);
    setFormKey((k) => k + 1);
  };

  const toggle = async (rule, active) => {
    setError(null);
    try {
      const updated = await api.setRuleActive(rule.ruleId, active);
      setRules((list) => list.map((r) => (r.ruleId === rule.ruleId ? updated : r)));
    } catch (e) {
      setError(e.message);
    }
  };

  const remove = async (rule) => {
    if (!window.confirm(`'${rule.name}' 규칙을 삭제할까요?\n삭제 내역은 관리자 이력에 기록됩니다.`)) return;
    setError(null);
    try {
      await api.deleteRule(rule.ruleId);
      if (editing?.ruleId === rule.ruleId) startCreate();
      loadRules();
    } catch (e) {
      setError(e.message);
    }
  };

  const onSaved = () => {
    loadRules();
    startCreate();
  };

  return (
    <>
      <header className="page-head">
        <div>
          <h1>위협 탐지 규칙</h1>
          <div className="muted sub">활성화된 규칙만 정규화 이벤트에 적용 · 조건 충족 시 위협 이벤트와 경보 생성</div>
        </div>
        <button type="button" className="btn pri" onClick={startCreate}>규칙 등록</button>
      </header>

      <div className="tabs" role="tablist" aria-label="탐지 탭">
        <button role="tab" aria-selected={tab === 'rules'} className={tab === 'rules' ? 'on' : ''}
          onClick={() => setTab('rules')}>
          탐지 규칙 <span className="muted">{rules.length}</span>
        </button>
        <button role="tab" aria-selected={tab === 'results'} className={tab === 'results' ? 'on' : ''}
          onClick={() => setTab('results')}>
          탐지 결과
        </button>
      </div>

      <ErrorBox error={error} />

      {tab === 'rules' ? (
        <div className="split">
          <div className="card flush grow">
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    <th>규칙 이름</th><th>탐지 방식</th><th>조건 · 임계값</th><th>기본 등급</th><th>상태</th>
                    <th><span className="sr-only">작업</span></th>
                  </tr>
                </thead>
                <tbody>
                  {rules.length === 0 && (
                    <tr><td colSpan={6} className="empty">등록된 탐지 규칙이 없습니다.</td></tr>
                  )}
                  {rules.map((r) => (
                    <tr key={r.ruleId} className={editing?.ruleId === r.ruleId ? 'sel' : ''}>
                      <td style={{ whiteSpace: 'normal', minWidth: 140 }}>
                        <div style={{ fontWeight: 600 }}>{r.name}</div>
                        <div className="muted" style={{ fontSize: 12 }}>{r.description}</div>
                      </td>
                      <td>{METHOD_LABEL[r.detectMethod]}</td>
                      <td className="mono" style={{ fontSize: 12, whiteSpace: 'normal', minWidth: 180, wordBreak: 'break-all' }}>{r.conditionText}</td>
                      <td><SeverityBadge value={r.severity} /></td>
                      <td><Switch on={r.active} onChange={(v) => toggle(r, v)} /></td>
                      <td style={{ textAlign: 'right' }}>
                        <button type="button" className="btn sm" onClick={() => startEdit(r)}>수정</button>{' '}
                        <button type="button" className="btn sm danger" onClick={() => remove(r)}>삭제</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <RuleForm
            key={formKey}
            rule={editing}
            logTypes={codes.logTypes}
            eventTypes={codes.eventTypes}
            onSaved={onSaved}
            onCancel={startCreate}
          />
        </div>
      ) : (
        <ThreatResults />
      )}
    </>
  );
}
