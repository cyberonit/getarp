const BASE = import.meta.env.VITE_API_BASE || '/api'

function token() { return localStorage.getItem('getarp_token') }

async function get(path) {
  const r = await fetch(BASE + path, {
    headers: token() ? { Authorization: `Bearer ${token()}` } : {},
  })
  if (!r.ok) throw new Error(`${r.status}`)
  return r.json()
}

export const api = {
  status: () => get('/status'),
  statusHistory: (h = 24) => get(`/status/history?hours=${h}`),
  ips: (order = 'threat_score') => get(`/ips?order=${order}&limit=200`),
  ipDetail: (ip) => get(`/ips/${ip}`),
  scans: () => get('/scans'),
  attacks: () => get('/attacks'),
  behavior: () => get('/behavior'),
  map: () => get('/map'),
  topCountries: (window = '1h') => get(`/top-countries?window=${window}`),
  topAS: (window = '1h') => get(`/top-as?window=${window}`),
  reports: () => get('/reports'),
  report: (id) => get(`/reports/${id}`),
  reportCsvUrl: (id) => `${BASE}/reports/${id}/csv`,

  async login(username, password) {
    const body = new URLSearchParams({ username, password })
    const r = await fetch(BASE + '/auth/login', { method: 'POST', body })
    if (!r.ok) throw new Error('bad credentials')
    const d = await r.json()
    localStorage.setItem('getarp_token', d.access_token)
    return d
  },
  logout() { localStorage.removeItem('getarp_token') },
  isAuthed: () => !!token(),

  docs: () => get('/docs'),
  docUrl: (name) => `${BASE}/docs/${name}`,

  latestEvents: (limit = 50) => get(`/events/latest?limit=${limit}`),
  crowdsecOverview: () => get('/admin/crowdsec/overview'),
  crowdsecDecisions: () => get('/admin/crowdsec/decisions'),

  settings: () => get('/admin/settings'),
  async saveSetting(key, value) {
    const r = await fetch(BASE + '/admin/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token()}` },
      body: JSON.stringify({ key, value }),
    })
    if (!r.ok) throw new Error('save failed')
    return r.json()
  },

  liveSocket(onMsg) {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const t = token()
    const url = `${proto}://${location.host}${BASE}/ws/status${t ? `?token=${encodeURIComponent(t)}` : ''}`
    const ws = new WebSocket(url)
    ws.onmessage = (e) => { try { onMsg(JSON.parse(e.data)) } catch {} }
    return ws
  },
}
