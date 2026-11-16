import { severityClass, severityLabel } from '../format.js';

export function SeverityBadge({ value }) {
  return <span className={`b ${severityClass(value)}`}>{severityLabel(value)}</span>;
}

export function Switch({ on, onChange, disabled }) {
  return (
    <button type="button" className={`sw ${on ? 'on' : ''}`} aria-pressed={on} disabled={disabled}
      onClick={() => onChange(!on)}>
      <span className="track"><span className="knob" /></span>
      {on ? '활성' : '비활성'}
    </button>
  );
}

export function ErrorBox({ error }) {
  if (!error) return null;
  return <div className="error" role="alert">{error}</div>;
}
