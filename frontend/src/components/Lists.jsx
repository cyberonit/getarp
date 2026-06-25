import React, { useEffect, useState } from 'react'
import { api } from '../lib/api.js'

const fmt = (t) => new Date(t).toLocaleString()

const SCAN_GROUPS = [['', 'None'], ['scan_type', 'Type'], ['as', 'AS']]

export function Scans({ onPick }) {
  const [rows, setRows] = useState([])
  const [window, setWindow] = useState('24h')
  const [groupBy, setGroupBy] = useState('')
  useEffect(() => {
    let cancelled = false
    api.scans(window, groupBy).then((d) => { if (!cancelled) setRows(d) }).catch(() => {})
    return () => { cancelled = true }
  }, [window, groupBy])

  const grouped = groupBy !== ''
  return (
    <div className="card"><h3>
      <span>scan correlation</span>
      <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <select value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
          {SCAN_GROUPS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        <select value={window} onChange={(e) => setWindow(e.target.value)}>
          {WINDOWS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        {rows.length}
      </span>
    </h3>
      <div className="body"><table>
        {grouped ? (<>
          <thead><tr><th>{groupBy === 'as' ? 'AS' : 'type'}</th><th>count</th><th>avg ports</th></tr></thead>
          <tbody>{rows.map((r, i) => (
            <tr key={i}>
              <td>{groupBy === 'as' ? (r.org || r.asn || '—') : (r.label || '—')}</td>
              <td>{r.n}</td><td>{r.avg_ports}</td></tr>
          ))}</tbody>
        </>) : (<>
          <thead><tr><th>time</th><th>ip</th><th>country</th><th>as</th><th>type</th><th>ports</th><th>port list</th></tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={r.id}><td className="muted">{fmt(r.ts)}</td>
              <td className="ip" onClick={() => onPick(r.src_ip)}>{r.src_ip}</td>
              <td>{r.country || '—'}</td><td className="muted">{r.org || r.asn || '—'}</td>
              <td><span className="tag scanner">{r.scan_type}</span></td>
              <td>{r.port_count}</td><td className="muted">{(r.ports || []).join(' ')}</td></tr>
          ))}</tbody>
        </>)}
      </table></div></div>
  )
}

const WINDOWS = [['1h', '1 h'], ['24h', '24 h'], ['7d', '7 d'], ['30d', '30 d'], ['1y', '1 y']]
const ATTACK_GROUPS = [['', 'None'], ['service', 'Service'], ['as', 'AS']]

export function Attacks({ onPick }) {
  const [rows, setRows] = useState([])
  const [window, setWindow] = useState('24h')
  const [groupBy, setGroupBy] = useState('')
  useEffect(() => {
    let cancelled = false
    api.attacks(window, groupBy).then((d) => { if (!cancelled) setRows(d) }).catch(() => {})
    return () => { cancelled = true }
  }, [window, groupBy])

  const grouped = groupBy !== ''
  return (
    <div className="card"><h3>
      <span>attack correlation</span>
      <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <select value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
          {ATTACK_GROUPS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        <select value={window} onChange={(e) => setWindow(e.target.value)}>
          {WINDOWS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        {rows.length}
      </span>
    </h3>
      <div className="body"><table>
        {grouped ? (<>
          <thead><tr><th>{groupBy === 'as' ? 'AS' : 'service'}</th><th>count</th><th>avg sev</th></tr></thead>
          <tbody>{rows.map((r, i) => (
            <tr key={i}>
              <td>{groupBy === 'as' ? (r.org || r.asn || '—') : (r.label || '—')}</td>
              <td>{r.n}</td><td>{r.avg_severity}</td></tr>
          ))}</tbody>
        </>) : (<>
          <thead><tr><th>time</th><th>ip</th><th>country</th><th>as</th><th>type</th><th>service</th><th>sev</th><th>evidence</th></tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={r.id}><td className="muted">{fmt(r.ts)}</td>
              <td className="ip" onClick={() => onPick(r.src_ip)}>{r.src_ip}</td>
              <td>{r.country || '—'}</td><td className="muted">{r.org || r.asn || '—'}</td>
              <td><span className="tag exploiter">{r.attack_type}</span></td>
              <td>{r.service || '—'}</td><td>{r.severity}</td>
              <td className="muted">{JSON.stringify(r.evidence).slice(0, 70)}</td></tr>
          ))}</tbody>
        </>)}
      </table></div></div>
  )
}

export function Behavior({ onPick }) {
  const [rows, setRows] = useState([])
  const [window, setWindow] = useState('24h')
  const [country, setCountry] = useState('')
  const [asn, setAsn] = useState('')
  const [tooling, setTooling] = useState('')
  const [tactic, setTactic] = useState('')
  const [opts, setOpts] = useState({ countries: [], asns: [], toolings: [], tactics: [] })

  useEffect(() => {
    let cancelled = false
    api.behavior('1y').then((all) => {
      if (cancelled) return
      const countries = [...new Set(all.map((r) => r.country).filter(Boolean))].sort()
      const asns = [...new Set(all.map((r) => r.asn).filter(Boolean))].sort()
      const toolings = [...new Set(all.flatMap((r) => r.tooling_hints || []))].sort()
      const tactics = [...new Set(all.flatMap((r) => r.tactics || []))].sort()
      setOpts({ countries, asns, toolings, tactics })
    }).catch(() => {})
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    let cancelled = false
    api.behavior(window, { country, asn, tooling, tactic })
      .then((d) => { if (!cancelled) setRows(d) }).catch(() => {})
    return () => { cancelled = true }
  }, [window, country, asn, tooling, tactic])

  return (
    <div className="card"><h3>
      <span>behavioral profiles</span>
      <span style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
        <select value={country} onChange={(e) => setCountry(e.target.value)}>
          <option value="">country</option>
          {opts.countries.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={asn} onChange={(e) => setAsn(e.target.value)}>
          <option value="">AS</option>
          {opts.asns.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <select value={tooling} onChange={(e) => setTooling(e.target.value)}>
          <option value="">tooling</option>
          {opts.toolings.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={tactic} onChange={(e) => setTactic(e.target.value)}>
          <option value="">tactics</option>
          {opts.tactics.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={window} onChange={(e) => setWindow(e.target.value)}>
          {WINDOWS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        {rows.length}
      </span>
    </h3>
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
                <tr><td className="muted">scanners / probers</td><td>{s.scans?.toLocaleString() ?? '—'}</td></tr>
                <tr><td className="muted">known attackers</td><td>{s.blocked_ips?.toLocaleString() ?? '0'}</td></tr>
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
