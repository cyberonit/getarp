const BASE = import.meta.env.VITE_API_BASE || '/api'

function token() { return localStorage.getItem('getarp_token') }

function authHeaders() {
  const t = token()
  return t ? { Authorization: `Bearer ${t}` } : {}
}

async function get(path) {
  const r = await fetch(BASE + path, { headers: authHeaders() })
  if (!r.ok) throw new Error(`${r.status}`)
  return r.json()
}

export const api = {
  status: () => get('/status'),
  statusHistory: (h = 24) => get(`/status/history?hours=${h}`),
  ips: (order = 'threat_score') => get(`/ips?order=${order}&limit=200`),
  ipDetail: (ip) => get(`/ips/${ip}`),
  scans: (window = '24h', groupBy = '') => {
    const p = new URLSearchParams({ window })
    if (groupBy) p.set('group_by', groupBy)
    return get(`/scans?${p}`)
  },
  attacks: (window = '24h', groupBy = '') => {
    const p = new URLSearchParams({ window })
    if (groupBy) p.set('group_by', groupBy)
    return get(`/attacks?${p}`)
  },
  behavior: (window = '24h') => get(`/behavior?window=${window}`),
  map: () => get('/map'),
  topCountries: (window = '1h') => get(`/top-countries?window=${window}`),
  topAS: (window = '1h') => get(`/top-as?window=${window}`),
  reports: () => get('/reports'),
  report: (id) => get(`/reports/${id}`),
  reportCsvUrl: (id) => `${BASE}/reports/${id}/csv`,

  async login(username, password) {
    const r = await fetch(BASE + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (!r.ok) throw new Error('bad credentials')
    const d = await r.json()
    localStorage.setItem('getarp_token', d.access_token)
    return d
  },
  async logout() {
    try {
      await fetch(BASE + '/auth/logout', { method: 'POST', headers: authHeaders() })
    } catch {}
    localStorage.removeItem('getarp_token')
  },
  isAuthed: () => !!token(),

  docs: () => get('/docs'),
  docUrl: (name) => `${BASE}/docs/${name}`,

  latestEvents: (limit = 50) => get(`/events/latest?limit=${limit}`),
  crowdsecOverview: () => get('/admin/crowdsec/overview'),
  crowdsecDecisions: () => get('/admin/crowdsec/decisions'),

  dockerServices: () => get('/admin/docker/services'),
  dockerLogs: (service, lines = 150) => get(`/admin/docker/logs/${service}?lines=${lines}`),
  dockerVersions: () => get('/admin/docker/versions'),
  async dockerPull(service) {
    const r = await fetch(BASE + `/admin/docker/pull/${service}`, {
      method: 'POST', headers: authHeaders(),
    })
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || 'pull failed') }
    return r.json()
  },
  async dockerRollback(service) {
    const r = await fetch(BASE + `/admin/docker/rollback/${service}`, {
      method: 'POST', headers: authHeaders(),
    })
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || 'rollback failed') }
    return r.json()
  },
  async dockerRestart(service) {
    const r = await fetch(BASE + `/admin/docker/restart/${service}`, {
      method: 'POST', headers: authHeaders(),
    })
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || 'restart failed') }
    return r.json()
  },

  settings: () => get('/admin/settings'),
  async saveSetting(key, value) {
    const r = await fetch(BASE + '/admin/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ key, value }),
    })
    if (!r.ok) throw new Error('save failed')
    return r.json()
  },

  liveSocket(onMsg) {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${proto}://${location.host}${BASE}/ws/status`
    const ws = new WebSocket(url)
    ws.onmessage = (e) => { try { onMsg(JSON.parse(e.data)) } catch {} }
    ws.onerror = () => {}
    return ws
  },
}
