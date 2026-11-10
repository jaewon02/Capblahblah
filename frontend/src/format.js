// 화면 표시용 라벨 · 색상 클래스

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const SEVERITY_LABEL = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info' };
const SEVERITY_CLASS = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'info' };

export const severityLabel = (s) => SEVERITY_LABEL[s] ?? s;
export const severityClass = (s) => SEVERITY_CLASS[s] ?? 'info';

export const ALERT_STATUS = {
  NEW: { label: '미확인', cls: 'st-new', next: 'ACK', nextLabel: '확인' },
  ACK: { label: '확인', cls: 'st-ack', next: 'RESOLVED', nextLabel: '처리 완료' },
  RESOLVED: { label: '처리 완료', cls: 'st-done', next: null, nextLabel: null },
};

export const METHOD_LABEL = { CONDITION: '조건 기반', THRESHOLD: '반복 행위' };

// detection_rule.group_by (명세서: SOURCE_IP/USER_ACCOUNT/TARGET)
export const GROUP_BY_OPTIONS = [
  { value: 'SOURCE_IP', label: '출발지 IP' },
  { value: 'USER_ACCOUNT', label: '사용자 계정' },
  { value: 'TARGET', label: '수집 대상' },
];

// 조건 필드 = normalized_event 컬럼명 또는 extra.<키>
export const CONDITION_FIELDS = [
  { value: 'event_type_code', label: '이벤트 유형' },
  { value: 'host_name', label: '호스트명' },
  { value: 'source_ip', label: '출발지 IP' },
  { value: 'dest_ip', label: '목적지 IP' },
  { value: 'dest_port', label: '목적지 포트' },
  { value: 'user_account', label: '사용자 계정' },
  { value: 'event_time', label: '발생 시각(KST 시)' },
  { value: 'extra.', label: '추가 필드(extra.키)' },
];

export const CONDITION_OPS = [
  { value: 'eq', label: '같음 (=)' },
  { value: 'ne', label: '다름 (≠)' },
  { value: 'in', label: '목록 중 하나 (쉼표 구분)' },
  { value: 'contains', label: '포함' },
  { value: 'regex', label: '정규식' },
  { value: 'between', label: '범위 안 (a-b)' },
  { value: 'not_between', label: '범위 밖 (a-b)' },
];

// event_time 전용
export const HOUR_OPS = [
  { value: 'hour_between', label: '시각 범위 안 (9-18)' },
  { value: 'hour_not_between', label: '시각 범위 밖 (9-18)' },
];

const pad = (n) => String(n).padStart(2, '0');

/** "2026-11-23T14:31:02" → "11-23 14:31:02" (오늘이면 시각만) */
export function formatTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const today = new Date();
  const sameDay =
    d.getFullYear() === today.getFullYear() && d.getMonth() === today.getMonth() && d.getDate() === today.getDate();
  return sameDay ? time : `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`;
}

export function todayIso() {
  const d = new Date();
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
