import React, { useEffect, useState, useRef } from 'react'
import { api } from '../lib/api.js'

export function Login({ onDone }) {
  const [u, setU] = useState(''); const [p, setP] = useState(''); const [err, setErr] = useState('')
  async function submit() {
    try { await api.login(u, p); onDone() }
    catch { setErr('Login failed — check your username and password.') }
  }
  return (
    <div className="center"><div className="login">
      <div className="brand"><b>getarp</b> ops<small>operator sign-in</small></div>
      <div style={{ marginTop: 18 }}>
        <label>username</label>
        <input value={u} onChange={(e) => setU(e.target.value)} autoFocus />
      </div>
      <div style={{ marginTop: 12 }}>
        <label>password</label>
        <input type="password" value={p} onChange={(e) => setP(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submit()} />
      </div>
      <button className="cta" onClick={submit}>Sign in</button>
      {err && <div className="err">{err}</div>}
    </div></div>
  )
}

export function Settings() {
  const [rows, setRows] = useState([]); const [msg, setMsg] = useState('')
  useEffect(() => { api.settings().then(setRows).catch(() => {}) }, [])
  async function save(key, value) {
    try {
      let v = value
      try { v = JSON.parse(value) } catch {}
      const r = await api.saveSetting(key, v)
      setMsg(r.note || 'Saved.')
    } catch { setMsg('Save failed.') }
  }
  return (
    <>
      <div className="card"><h3><span>runtime settings</span><span>admin</span></h3>
        <div className="body">
          <p className="muted">Change detection thresholds and the active intelligence provider.
            Some changes take effect on the next service restart.</p>
          <table><thead><tr><th>setting</th><th>value</th><th></th></tr></thead>
            <tbody>{rows.map((r) => (
              <SettingRow key={r.key} row={r} onSave={save} />
            ))}</tbody></table>
          {msg && <div className="muted" style={{ marginTop: 10 }}>{msg}</div>}
        </div></div>
      <ServiceLogs />
      <ServiceUpdates />
      <LiveTraffic />
      <BlockedIPs />
      <CrowdSecConsole />
    </>
  )
}

function ServiceLogs() {
  const [services, setServices] = useState([])
  const [selected, setSelected] = useState('__all__')
  const [lines, setLines] = useState(150)
  const [log, setLog] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const logRef = useRef(null)

  useEffect(() => {
    api.dockerServices()
      .then((svc) => setServices(svc))
      .catch(() => setErr('Could not load services.'))
  }, [])

  const load = () => {
    if (!selected) return
    setLoading(true); setErr('')
    if (selected === '__all__') {
      Promise.all(services.map((s) => api.dockerLogs(s.name, lines).catch(() => ({ log: '' }))))
        .then((results) => {
          const combined = results
            .map((d, i) => (d.log || '').split('\n').filter(Boolean)
              .map((l) => `[${services[i].name}] ${l}`).join('\n'))
            .filter(Boolean).join('\n')
          setLog(combined); setLoading(false)
        })
        .catch(() => { setErr('Could not load logs.'); setLoading(false) })
    } else {
      api.dockerLogs(selected, lines)
        .then((d) => { setLog(d.log || ''); setLoading(false) })
        .catch(() => { setErr('Could not load logs.'); setLoading(false) })
    }
  }

  useEffect(() => { if (selected && (selected !== '__all__' || services.length)) load() }, [selected, lines, services])
  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight }, [log])

  return (
    <div className="card"><h3><span>service logs</span>
      <span>
        <select value={selected} onChange={(e) => setSelected(e.target.value)}
          style={{ marginRight: 10 }}>
          <option value="__all__">all logs</option>
          {services.map((s) => (
            <option key={s.name} value={s.name}>{s.name} ({s.status})</option>
          ))}
        </select>
        {[150, 500, 1000].map((n) => (
          <a key={n} onClick={() => setLines(n)}
            style={{ marginLeft: 8, fontWeight: n === lines ? 'bold' : 'normal' }}>{n}</a>
        ))}
        <a onClick={load} style={{ marginLeft: 12 }}>{loading ? 'loading...' : 'refresh'}</a>
      </span>
    </h3>
      <div className="body">
        <p className="muted">Docker container logs for troubleshooting. Select a service and line count.</p>
        <div ref={logRef} className="log-viewer">
          {log || (loading ? 'Loading...' : 'No log output.')}
        </div>
        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
      </div></div>
  )
}

function ServiceUpdates() {
  const [versions, setVersions] = useState([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState({})
  const [msgs, setMsgs] = useState({})

  const load = () => {
    setErr('')
    api.dockerVersions()
      .then(setVersions)
      .catch(() => setErr('Could not load service versions.'))
  }

  useEffect(() => { load() }, [])

  const setMsg = (svc, msg) => setMsgs((p) => ({ ...p, [svc]: msg }))
  const setBusyFlag = (svc, v) => setBusy((p) => ({ ...p, [svc]: v }))

  const restart = async (svc) => {
    setBusyFlag(svc, true); setMsg(svc, '')
    try {
      const r = await api.dockerRestart(svc)
      setMsg(svc, r.note || `Restarted (${r.status}).`)
      load()
    } catch (e) { setMsg(svc, e.message) }
    setBusyFlag(svc, false)
  }

  return (
    <div className="card"><h3><span>service versions</span>
      <span><a onClick={load}>refresh</a></span>
    </h3>
      <div className="body">
        <p className="muted">Docker images for all services. Restart a service here;
          image updates are a host-side operation (see maintenance/check-updates.sh).</p>
        <table><thead><tr>
          <th>service</th><th>image</th><th>image id</th><th>status</th><th>actions</th>
        </tr></thead>
          <tbody>{versions.map((v) => (
            <tr key={v.service}>
              <td>{v.service}</td>
              <td className="muted">{v.image}</td>
              <td className="muted">{v.image_short_id}</td>
              <td><span className={`tag ${v.status === 'running' ? 'scanner' : ''}`}>{v.status}</span></td>
              <td className="update-actions">
                <a onClick={() => restart(v.service)}
                  className={busy[v.service] ? 'disabled' : ''}>restart</a>
                {msgs[v.service] && <span className="muted" style={{ marginLeft: 8 }}>{msgs[v.service]}</span>}
              </td>
            </tr>
          ))}</tbody></table>
        {versions.length === 0 && !err && <div className="muted">loading...</div>}
        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
      </div></div>
  )
}

function LiveTraffic() {
  const [events, setEvents] = useState([])
  const [limit, setLimit] = useState(20)
  const [err, setErr] = useState('')
  const load = () => { api.latestEvents(limit).then(setEvents).catch(() => setErr('Could not load events.')) }
  useEffect(() => { load() }, [limit])
  return (
    <div className="card"><h3><span>live honeypot traffic</span>
      <span>
        {[20, 50].map((n) => (
          <a key={n} onClick={() => setLimit(n)}
            style={{ marginLeft: 8, fontWeight: n === limit ? 'bold' : 'normal' }}>{n}</a>
        ))}
        <a onClick={load} style={{ marginLeft: 12 }}>refresh</a>
      </span>
    </h3>
      <div className="body" style={{ maxHeight: 420, overflowY: 'auto' }}>
        <table><thead><tr><th>time</th><th>src_ip</th><th>service</th><th>type</th><th>port</th><th>user</th><th>command / signature</th></tr></thead>
          <tbody>{events.map((e, i) => (
            <tr key={i}>
              <td className="muted">{new Date(e.ts).toLocaleTimeString()}</td>
              <td>{e.src_ip}</td>
              <td>{e.service || '—'}</td>
              <td className="muted">{e.event_type}</td>
              <td>{e.dst_port ?? '—'}</td>
              <td className="muted">{e.username || '—'}</td>
              <td className="muted">{e.command || e.signature || '—'}</td>
            </tr>
          ))}</tbody></table>
        {events.length === 0 && <div className="muted">no events yet</div>}
        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
      </div></div>
  )
}

function BlockedIPs() {
  const [rows, setRows] = useState([])
  const [err, setErr] = useState('')
  const load = () => { api.crowdsecDecisions().then(setRows).catch(() => setErr('Could not reach CrowdSec LAPI.')) }
  useEffect(() => { load() }, [])
  return (
    <div className="card"><h3><span>blocked IPs (nftables)</span><span>{rows.length} active bans</span></h3>
      <div className="body" style={{ maxHeight: 420, overflowY: 'auto' }}>
        <p className="muted">IPs currently banned by the CrowdSec firewall bouncer.</p>
        <table><thead><tr><th>IP</th><th>scenario</th><th>type</th><th>duration</th></tr></thead>
          <tbody>{rows.map((d) => (
            <tr key={d.id}>
              <td>{d.ip}</td>
              <td className="muted">{d.scenario || '—'}</td>
              <td>{d.type || '—'}</td>
              <td className="muted">{d.duration || '—'}</td>
            </tr>
          ))}</tbody></table>
        {rows.length === 0 && !err && <div className="muted">no active bans</div>}
        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
      </div></div>
  )
}

function CrowdSecConsole() {
  const [data, setData] = useState(null); const [err, setErr] = useState('')
  useEffect(() => { api.crowdsecOverview().then(setData).catch(() => setErr('Could not reach CrowdSec LAPI.')) }, [])
  return (
    <div className="card"><h3><span>crowdsec console</span><span>{data?.total_decisions ?? '—'} decisions</span></h3>
      <div className="body">
        <p className="muted">{data?.local_decisions ?? '—'} bans from this sensor's own detections,
          plus {data?.capi_blocklist ?? '—'} from the CrowdSec community (CAPI) blocklist.
          Local decisions by scenario and type:</p>
        <div className="grid2">
          <div>
            <table><thead><tr><th>scenario</th><th>count</th></tr></thead>
              <tbody>{(data?.by_scenario || []).map((s) => (
                <tr key={s.scenario}><td className="muted">{s.scenario}</td><td>{s.count}</td></tr>
              ))}</tbody></table>
          </div>
          <div>
            <table><thead><tr><th>type</th><th>count</th></tr></thead>
              <tbody>{(data?.by_type || []).map((t) => (
                <tr key={t.type}><td className="muted">{t.type}</td><td>{t.count}</td></tr>
              ))}</tbody></table>
          </div>
        </div>
        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
      </div></div>
  )
}

export function Docs() {
  const [rows, setRows] = useState([]); const [err, setErr] = useState('')
  useEffect(() => { api.docs().then(setRows).catch(() => setErr('Could not load documents.')) }, [])
  return (
    <div className="card"><h3><span>documents</span></h3>
      <div className="body">
        <p className="muted">Architecture and design documents for this deployment.</p>
        <table><thead><tr><th>document</th><th>size</th><th></th></tr></thead>
          <tbody>
            <tr>
              <td>Source repository</td>
              <td>github.com</td>
              <td><a href="https://github.com/cyberonit/getarp" target="_blank" rel="noreferrer">open</a></td>
            </tr>
            {rows.map((r) => (
              <tr key={r.name}>
                <td>{r.label}</td>
                <td>{(r.size / 1024).toFixed(0)} KB</td>
                <td><a href={api.docUrl(r.name)} target="_blank" rel="noreferrer">open</a></td>
              </tr>
            ))}
          </tbody></table>
        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
      </div></div>
  )
}

function SettingRow({ row, onSave }) {
  const [v, setV] = useState(JSON.stringify(row.value))
  return (
    <tr><td>{row.key}</td>
      <td><input value={v} onChange={(e) => setV(e.target.value)} style={{ marginTop: 0 }} /></td>
      <td><a onClick={() => onSave(row.key, v)}>save</a></td></tr>
  )
}
