import { useState } from 'react';
import { api } from '../api.js';
import {
  CONDITION_FIELDS, CONDITION_OPS, GROUP_BY_OPTIONS, HOUR_OPS, SEVERITIES, severityLabel,
} from '../format.js';
import { ErrorBox } from '../components/common.jsx';

// 서버 조건 {field:"extra.COMMAND", value:[...]} ↔ 화면 {field:"extra.", extraKey:"COMMAND", value:"a, b"}
const toFormCondition = (c) => ({
  field: c.field.startsWith('extra.') ? 'extra.' : c.field,
  extraKey: c.field.startsWith('extra.') ? c.field.slice(6) : '',
  op: c.op,
  value: Array.isArray(c.value) ? c.value.join(', ') : c.value ?? '',
});

const toApiCondition = (c) => ({
  field: c.field === 'extra.' ? `extra.${c.extraKey.trim()}` : c.field,
  op: c.op,
  value: c.op === 'in' ? splitList(c.value) : c.value,
});

const splitList = (s) => s.split(',').map((v) => v.trim()).filter(Boolean);

function initialForm(rule) {
  if (!rule) {
    // 시간 창 · 임계 횟수 기본값 = system_setting detect.default_window_sec(300) · detect.default_threshold(10)
    return {
      name: '', description: '', detectMethod: 'THRESHOLD', logTypeCode: '', eventTypeCode: '',
      groupBy: 'SOURCE_IP', windowMin: '5', thresholdCount: '10', severity: 'HIGH', suppressMin: '0',
      mitreTechnique: '', conditions: [], exceptIps: '', exceptUsers: '',
    };
  }
  const ex = rule.exceptions ?? {};
  return {
    name: rule.name,
    description: rule.description ?? '',
    detectMethod: rule.detectMethod,
    logTypeCode: rule.logTypeCode ?? '',
    eventTypeCode: rule.eventTypeCode ?? '',
    groupBy: rule.groupBy ?? '',
    windowMin: rule.timeWindowSec ? String(rule.timeWindowSec / 60) : '5',
    thresholdCount: rule.thresholdCount ? String(rule.thresholdCount) : '10',
    severity: rule.severity,
    suppressMin: String((rule.suppressSec ?? 0) / 60),
    mitreTechnique: rule.mitreTechnique ?? '',
    conditions: rule.conditions.map(toFormCondition),
    exceptIps: (ex.source_ip ?? []).join(', '),
    exceptUsers: (ex.user_account ?? []).join(', '),
  };
}

const toNumber = (s) => (s === '' || s == null ? null : Number(s));

/** 규칙 등록 · 수정 폼 (No 120–121, 125). 입력 길이는 테이블 명세서 컬럼 길이 기준. */
export default function RuleForm({ rule, logTypes, eventTypes, onSaved, onCancel }) {
  const [form, setForm] = useState(() => initialForm(rule));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const isThreshold = form.detectMethod === 'THRESHOLD';
  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));
  const visibleEventTypes = eventTypes.filter((t) => !form.logTypeCode || t.logTypeCode === form.logTypeCode);

  const setCondition = (i, patch) =>
    setForm((f) => ({ ...f, conditions: f.conditions.map((c, j) => (j === i ? { ...c, ...patch } : c)) }));
  const changeField = (i, field) =>
    setCondition(i, field === 'event_time' ? { field, op: 'hour_not_between', value: '9-18' } : { field, op: 'eq' });
  const addCondition = () =>
    setForm((f) => ({ ...f, conditions: [...f.conditions, { field: 'user_account', extraKey: '', op: 'eq', value: '' }] }));
  const removeCondition = (i) => setForm((f) => ({ ...f, conditions: f.conditions.filter((_, j) => j !== i) }));

  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    const windowMin = toNumber(form.windowMin);
    const exceptions = {};
    if (splitList(form.exceptIps).length) exceptions.source_ip = splitList(form.exceptIps);
    if (splitList(form.exceptUsers).length) exceptions.user_account = splitList(form.exceptUsers);
    const body = {
      name: form.name,
      description: form.description,
      detectMethod: form.detectMethod,
      logTypeCode: form.logTypeCode || null,
      eventTypeCode: form.eventTypeCode || null,
      conditions: form.conditions.map(toApiCondition),
      groupBy: form.groupBy || null,
      timeWindowSec: isThreshold && windowMin != null ? Math.round(windowMin * 60) : null,
      thresholdCount: isThreshold ? toNumber(form.thresholdCount) : null,
      severity: form.severity,
      suppressSec: Math.round((toNumber(form.suppressMin) ?? 0) * 60),
      exceptions,
      mitreTechnique: form.mitreTechnique || null,
    };
    setSaving(true);
    try {
      if (rule) await api.updateRule(rule.ruleId, body);
      else await api.createRule(body);
      onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <form className="card side-card stack" aria-label={rule ? '탐지 규칙 수정' : '탐지 규칙 등록'} onSubmit={submit}>
      <h2 style={{ margin: 0 }}>
        {rule ? '규칙 수정' : '규칙 등록'}
        {rule && <span className="muted" style={{ fontSize: 12, fontWeight: 400, marginLeft: 8 }}>v{rule.version}</span>}
      </h2>

      <div className="field">
        <label htmlFor="rn">규칙 이름 (필수)</label>
        <input id="rn" type="text" required maxLength={100} placeholder="예: SSH 반복 인증 실패"
          value={form.name} onChange={set('name')} />
      </div>
      <div className="field">
        <label htmlFor="rd">설명</label>
        <textarea id="rd" placeholder="규칙의 목적" maxLength={500} value={form.description} onChange={set('description')} />
      </div>
      <div className="field">
        <label htmlFor="rk">탐지 방식</label>
        <select id="rk" value={form.detectMethod}
          onChange={(e) => setForm((f) => ({
            ...f, detectMethod: e.target.value,
            groupBy: e.target.value === 'THRESHOLD' && !f.groupBy ? 'SOURCE_IP' : f.groupBy,
          }))}>
          <option value="THRESHOLD">반복 행위 탐지 (시간 내 횟수)</option>
          <option value="CONDITION">조건 기반 탐지 (패턴 일치)</option>
        </select>
      </div>
      <div className="grid2">
        <div className="field">
          <label htmlFor="rt">로그 유형</label>
          <select id="rt" value={form.logTypeCode}
            onChange={(e) => setForm((f) => ({ ...f, logTypeCode: e.target.value, eventTypeCode: '' }))}>
            <option value="">전체</option>
            {logTypes.map((t) => <option key={t.logTypeCode} value={t.logTypeCode}>{t.name}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="re">이벤트 유형</label>
          <select id="re" value={form.eventTypeCode} onChange={set('eventTypeCode')}>
            <option value="">선택 안 함</option>
            {visibleEventTypes.map((t) => <option key={t.eventTypeCode} value={t.eventTypeCode}>{t.eventTypeCode}</option>)}
          </select>
        </div>
      </div>

      <div className="field">
        <label>추가 조건 <span className="hint">— 모두 만족해야 탐지</span></label>
        {form.conditions.map((c, i) => {
          const ops = c.field === 'event_time' ? HOUR_OPS : CONDITION_OPS;
          return (
            <div key={i} className="stack" style={{ gap: 6 }}>
              <div className="cond-row">
                <select aria-label="필드" value={c.field} onChange={(e) => changeField(i, e.target.value)}>
                  {CONDITION_FIELDS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
                </select>
                <select aria-label="연산자" value={c.op} onChange={(e) => setCondition(i, { op: e.target.value })}>
                  {ops.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                <input aria-label="값" value={c.value} required
                  placeholder={c.op.includes('between') ? '9-18' : c.op === 'in' ? 'a, b, c' : '값'}
                  onChange={(e) => setCondition(i, { value: e.target.value })} />
                <button type="button" className="btn sm ghost" aria-label="조건 삭제" onClick={() => removeCondition(i)}>✕</button>
              </div>
              {c.field === 'extra.' && (
                <input aria-label="추가 필드 키" placeholder="extra 키 (예: USER, COMMAND, path)" required
                  value={c.extraKey} onChange={(e) => setCondition(i, { extraKey: e.target.value })} />
              )}
            </div>
          );
        })}
        <button type="button" className="btn sm" style={{ alignSelf: 'flex-start' }} onClick={addCondition}>+ 조건 추가</button>
      </div>

      <div className="field">
        <label htmlFor="rg">그룹 기준{isThreshold && ' (필수)'}</label>
        <select id="rg" value={form.groupBy} onChange={set('groupBy')} required={isThreshold}>
          {!isThreshold && <option value="">자동 (호스트명 → 출발지 IP)</option>}
          {GROUP_BY_OPTIONS.map((g) => <option key={g.value} value={g.value}>{g.label}</option>)}
        </select>
      </div>

      {isThreshold && (
        <div className="grid2">
          <div className="field">
            <label htmlFor="rw">시간 창 (분)</label>
            <input id="rw" type="number" min="1" step="1" required value={form.windowMin} onChange={set('windowMin')} />
          </div>
          <div className="field">
            <label htmlFor="rc">임계 횟수</label>
            <input id="rc" type="number" min="1" step="1" required value={form.thresholdCount} onChange={set('thresholdCount')} />
          </div>
        </div>
      )}

      <div className="grid2">
        <div className="field">
          <label htmlFor="rgr">기본 위험 등급</label>
          <select id="rgr" value={form.severity} onChange={set('severity')}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{severityLabel(s)}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="rs">중복 억제 (분)</label>
          <input id="rs" type="number" min="0" step="1" required value={form.suppressMin} onChange={set('suppressMin')} />
        </div>
      </div>

      <details>
        <summary className="hint" style={{ cursor: 'pointer' }}>[권장] 예외 조건 · ATT&CK 기법</summary>
        <div className="stack" style={{ marginTop: 10 }}>
          <div className="field">
            <label htmlFor="rxi">예외 출발지 IP (쉼표 구분, CIDR 가능)</label>
            <input id="rxi" placeholder="예: 192.0.2.0/28, 10.0.0.5" value={form.exceptIps} onChange={set('exceptIps')} />
          </div>
          <div className="field">
            <label htmlFor="rxu">예외 사용자 계정 (쉼표 구분)</label>
            <input id="rxu" placeholder="예: svc-scanner" value={form.exceptUsers} onChange={set('exceptUsers')} />
          </div>
          <div className="field">
            <label htmlFor="rm">ATT&CK 기법</label>
            <input id="rm" maxLength={20} placeholder="예: T1110" value={form.mitreTechnique} onChange={set('mitreTechnique')} />
          </div>
        </div>
      </details>

      <ErrorBox error={error} />

      <div className="actions">
        <button type="button" className="btn" onClick={onCancel}>취소</button>
        <button type="submit" className="btn pri" disabled={saving}>{rule ? '저장' : '등록'}</button>
      </div>
      {rule && <div className="hint">저장하면 규칙 버전이 올라가고 변경 내역이 관리자 이력에 기록됩니다.</div>}
    </form>
  );
}
