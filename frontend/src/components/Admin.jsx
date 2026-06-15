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
  )
}

export function Docs() {
  const [rows, setRows] = useState([]); const [err, setErr] = useState('')
  useEffect(() => { api.docs().then(setRows).catch(() => setErr('Could not load documents.')) }, [])
  async function open(name) {
    try {
      const url = await api.docBlobUrl(name)
      window.open(url, '_blank')
    } catch { setErr('Download failed.') }
  }
  return (
    <div className="card"><h3><span>documents</span><span>admin</span></h3>
      <div className="body">
        <p className="muted">Architecture and design documents for this deployment.</p>
        <table><thead><tr><th>document</th><th>size</th><th></th></tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={r.name}>
              <td>{r.label}</td>
              <td>{(r.size / 1024).toFixed(0)} KB</td>
              <td><a onClick={() => open(r.name)}>open</a></td>
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
