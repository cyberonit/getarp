const BASE = import.meta.env.VITE_API_BASE || '/api'

let csrfToken = sessionStorage.getItem('csrf') || ''

function mutHeaders() {
  return { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken }
}

async function get(path) {
  const r = await fetch(BASE + path, { credentials: 'same-origin' })
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
  behavior: (window = '24h', limit = 100) => get(`/behavior?window=${window}&limit=${limit}`),
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
      credentials: 'same-origin',
      body: JSON.stringify({ username, password }),
    })
    if (!r.ok) throw new Error('bad credentials')
    const d = await r.json()
    csrfToken = d.csrf_token || ''
    sessionStorage.setItem('csrf', csrfToken)
    return d
  },
  async logout() {
    try {
      await fetch(BASE + '/auth/logout', {
        method: 'POST', headers: mutHeaders(), credentials: 'same-origin',
      })
    } catch {}
    csrfToken = ''
    sessionStorage.removeItem('csrf')
  },
  isAuthed: () => !!csrfToken,

  docs: () => get('/docs'),
  docUrl: (name) => `${BASE}/docs/${name}`,

  latestEvents: (limit = 50) => get(`/events/latest?limit=${limit}`),
  crowdsecOverview: () => get('/admin/crowdsec/overview'),
  crowdsecDecisions: () => get('/admin/crowdsec/decisions'),

  dockerServices: () => get('/admin/docker/services'),
  dockerLogs: (service, lines = 150) => get(`/admin/docker/logs/${service}?lines=${lines}`),
  dockerVersions: () => get('/admin/docker/versions'),
  async dockerRestart(service) {
    const r = await fetch(BASE + `/admin/docker/restart/${service}`, {
      method: 'POST', headers: mutHeaders(), credentials: 'same-origin',
    })
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || 'restart failed') }
    return r.json()
  },

  settings: () => get('/admin/settings'),
  async saveSetting(key, value) {
    const r = await fetch(BASE + '/admin/settings', {
      method: 'PUT',
      headers: mutHeaders(),
      credentials: 'same-origin',
      body: JSON.stringify({ key, value }),
    })
    if (!r.ok) throw new Error('save failed')
    return r.json()
  },

  async liveSocket(onMsg) {
    // The status stream is public; a ticket is only fetched when signed in
    // (kept for parity with authenticated sessions — the server consumes it).
    let ticket = ''
    if (csrfToken) {
      try {
        const t = await fetch(BASE + '/auth/ws-ticket', {
          method: 'POST', headers: mutHeaders(), credentials: 'same-origin',
        })
        if (t.ok) ticket = (await t.json()).ticket || ''
      } catch {}
    }
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${proto}://${location.host}${BASE}/ws/status${ticket ? `?ticket=${ticket}` : ''}`
    const ws = new WebSocket(url)
    ws.onmessage = (e) => { try { onMsg(JSON.parse(e.data)) } catch {} }
    ws.onerror = () => {}
    return ws
  },
}
