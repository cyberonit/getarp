import React, { useEffect, useState } from 'react'
import { api } from '../lib/api.js'

const fmt = (t) => new Date(t).toLocaleString()

export function Scans({ onPick }) {
  const [rows, setRows] = useState([])
  useEffect(() => { api.scans().then(setRows).catch(() => {}) }, [])
  return (
    <div className="card"><h3><span>scan correlation</span><span>{rows.length}</span></h3>
      <div className="body"><table>
        <thead><tr><th>time</th><th>ip</th><th>country</th><th>as</th><th>type</th><th>ports</th><th>port list</th></tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={r.id}><td className="muted">{fmt(r.ts)}</td>
            <td className="ip" onClick={() => onPick(r.src_ip)}>{r.src_ip}</td>
            <td>{r.country || '—'}</td><td className="muted">{r.org || r.asn || '—'}</td>
            <td><span className="tag scanner">{r.scan_type}</span></td>
            <td>{r.port_count}</td><td className="muted">{(r.ports || []).join(' ')}</td></tr>
        ))}</tbody></table></div></div>
  )
}

export function Attacks({ onPick }) {
  const [rows, setRows] = useState([])
  useEffect(() => { api.attacks().then(setRows).catch(() => {}) }, [])
  return (
    <div className="card"><h3><span>attack correlation</span><span>{rows.length}</span></h3>
      <div className="body"><table>
        <thead><tr><th>time</th><th>ip</th><th>country</th><th>as</th><th>type</th><th>service</th><th>sev</th><th>evidence</th></tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={r.id}><td className="muted">{fmt(r.ts)}</td>
            <td className="ip" onClick={() => onPick(r.src_ip)}>{r.src_ip}</td>
            <td>{r.country || '—'}</td><td className="muted">{r.org || r.asn || '—'}</td>
            <td><span className="tag exploiter">{r.attack_type}</span></td>
            <td>{r.service || '—'}</td><td>{r.severity}</td>
            <td className="muted">{JSON.stringify(r.evidence).slice(0, 70)}</td></tr>
        ))}</tbody></table></div></div>
  )
}

export function Behavior({ onPick }) {
  const [rows, setRows] = useState([])
  useEffect(() => { api.behavior().then(setRows).catch(() => {}) }, [])
  return (
    <div className="card"><h3><span>behavioral profiles</span><span>{rows.length}</span></h3>
      <div className="body"><table>
        <thead><tr><th>ip</th><th>country</th><th>as</th><th>score</th><th>sessions</th><th>tooling</th><th>tactics</th></tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={r.src_ip}>
            <td className="ip" onClick={() => onPick(r.src_ip)}>{r.src_ip}</td>
            <td>{r.country || '—'}</td><td className="muted">{r.org || r.asn || '—'}</td>
            <td className="score s-hi">{Math.round(r.threat_score)}</td>
            <td>{r.sessions}</td>
            <td className="muted">{(r.tooling_hints || []).join(', ') || '—'}</td>
            <td className="muted">{(r.tactics || []).join(', ') || '—'}</td></tr>
        ))}</tbody></table></div></div>
  )
}

export function Reports() {
  const [rows, setRows] = useState([])
  const [sel, setSel] = useState(null)
  useEffect(() => { api.reports().then(setRows).catch(() => {}) }, [])
  const s = sel?.summary
  return (
    <div className="grid2">
      <div className="card"><h3><span>reports</span><span>{rows.length}</span></h3>
        <div className="body"><table>
          <thead><tr><th>created</th><th>kind</th><th>events</th><th></th><th></th></tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={r.id} style={sel?.id === r.id ? { background: 'var(--card-hover)' } : {}}>
              <td className="muted">{fmt(r.created_at)}</td><td>{r.kind}</td>
              <td>{r.summary?.events ?? '—'}</td>
              <td><a onClick={() => setSel(r)}>view</a></td>
              <td><a href={api.reportCsvUrl(r.id)} target="_blank" rel="noreferrer">csv</a></td></tr>
          ))}</tbody></table>
          {rows.length === 0 && <div className="muted">no reports yet — first daily report runs at 06:00 UTC</div>}
        </div></div>
      <div className="card"><h3><span>{sel ? `${sel.kind} report — ${fmt(sel.created_at)}` : 'preview'}</span></h3>
        <div className="body">
          {!s && <div className="muted">select a report</div>}
          {s && <>
            <table>
              <tbody>
                <tr><td className="muted">events</td><td>{s.events?.toLocaleString() ?? '—'}</td></tr>
                <tr><td className="muted">unique IPs</td><td>{s.unique_ips?.toLocaleString() ?? '—'}</td></tr>
                <tr><td className="muted">scans</td><td>{s.scans?.toLocaleString() ?? '—'}</td></tr>
                <tr><td className="muted">IPs blocked</td><td>{s.blocked_ips?.toLocaleString() ?? '0'}</td></tr>
              </tbody>
            </table>
            {s.attacks_by_type?.length > 0 && <>
              <h3 style={{ marginTop: 16 }}><span>attacks by type</span></h3>
              <table>
                <thead><tr><th>type</th><th>count</th></tr></thead>
                <tbody>{s.attacks_by_type.map((a, i) => (
                  <tr key={i}><td>{a.attack_type}</td><td>{a.n}</td></tr>
                ))}</tbody>
              </table>
            </>}
          </>}
        </div>
      </div>
    </div>
  )
}
