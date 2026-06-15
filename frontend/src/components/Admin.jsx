import React, { useEffect, useState } from 'react'
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
      <BouncerManager />
      <CrowdSecConsole />
      <CowrieViewer />
    </>
  )
}

function BouncerManager() {
  const [rows, setRows] = useState([]); const [err, setErr] = useState('')
  useEffect(() => { api.crowdsecDecisions().then(setRows).catch(() => setErr('Could not reach CrowdSec LAPI.')) }, [])
  return (
    <div className="card"><h3><span>bouncer manager</span><span>{rows.length} active bans</span></h3>
      <div className="body">
        <p className="muted">IPs currently blocked by the host firewall bouncer (live from the CrowdSec LAPI).</p>
        <table><thead><tr><th>ip</th><th>scenario</th><th>type</th><th>duration</th><th>origin</th></tr></thead>
          <tbody>{rows.map((d) => (
            <tr key={d.id}>
              <td>{d.ip}</td><td className="muted">{d.scenario}</td><td>{d.type}</td>
              <td>{d.duration}</td><td className="muted">{d.origin}</td>
            </tr>
          ))}</tbody></table>
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

function CowrieViewer() {
  const [rows, setRows] = useState([]); const [err, setErr] = useState('')
  useEffect(() => { api.cowrieSessions().then(setRows).catch(() => setErr('Could not read Cowrie logs.')) }, [])
  return (
    <div className="card"><h3><span>cowrie honeypot</span><span>{rows.length} recent sessions</span></h3>
      <div className="body">
        <p className="muted">Recent SSH/Telnet sessions: login attempts, commands run, and file transfers.</p>
        <table><thead><tr><th>src ip</th><th>proto</th><th>logins</th><th>commands</th><th>files</th></tr></thead>
          <tbody>{rows.map((s) => (
            <tr key={s.session}>
              <td>{s.src_ip}</td><td className="muted">{s.protocol}</td>
              <td>{s.logins.map((l, i) => (
                <div key={i} className="muted">{l.username}/{l.password}{l.success ? ' ✓' : ''}</div>
              ))}</td>
              <td>{s.commands.map((c, i) => <div key={i} className="muted">{c}</div>)}</td>
              <td>{s.files.map((f, i) => <div key={i} className="muted">{f.direction}: {f.url || f.outfile}</div>)}</td>
            </tr>
          ))}</tbody></table>
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
          <tbody>{rows.map((r) => (
            <tr key={r.name}>
              <td>{r.label}</td>
              <td>{(r.size / 1024).toFixed(0)} KB</td>
              <td><a href={api.docUrl(r.name)} target="_blank" rel="noreferrer">open</a></td>
            </tr>
          ))}</tbody></table>
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
