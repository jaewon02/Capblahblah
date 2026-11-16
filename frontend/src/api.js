// 백엔드 API 호출. 오류 시 서버의 {"message"}를 담은 Error를 던진다.
async function request(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let message = `요청 실패 (${res.status})`;
    try {
      const data = await res.json();
      if (data.message) message = data.message;
    } catch {
      /* 본문 없음 */
    }
    throw new Error(message);
  }
  return res.status === 204 ? null : res.json();
}

function query(params) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') q.append(k, v);
  });
  const s = q.toString();
  return s ? `?${s}` : '';
}

export const api = {
  // 공통 코드
  logTypes: () => request('GET', '/api/codes/log-types'),
  eventTypes: () => request('GET', '/api/codes/event-types'),

  // 탐지 규칙 (5.1)
  rules: () => request('GET', '/api/rules'),
  createRule: (body) => request('POST', '/api/rules', body),
  updateRule: (id, body) => request('PUT', `/api/rules/${id}`, body),
  setRuleActive: (id, active) => request('PATCH', `/api/rules/${id}/active`, { active }),
  deleteRule: (id) => request('DELETE', `/api/rules/${id}`),

  // 탐지 결과 (5.3)
  threats: (params = {}) => request('GET', `/api/threats${query(params)}`),
  threat: (id) => request('GET', `/api/threats/${id}`),

  // 경보 (5.4)
  alerts: (params = {}) => request('GET', `/api/alerts${query(params)}`),
  alertSummary: (params = {}) => request('GET', `/api/alerts/summary${query(params)}`),
  changeAlertStatus: (id, status) => request('PATCH', `/api/alerts/${id}/status`, { status }),
  setFalsePositive: (id, falsePositive, comment) =>
    request('PATCH', `/api/alerts/${id}/false-positive`, { falsePositive, comment }),
};
