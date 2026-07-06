import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../lib/api.js'

const fmt = (t) => new Date(t).toLocaleString()
const fmtDate = (t) => t ? new Date(t).toISOString().slice(0, 10) : ''
const WINDOWS = [['1h', '1 h'], ['24h', '24 h'], ['7d', '7 d'], ['30d', '30 d'], ['1y', '1 y']]
const scoreClass = (s) => s >= 70 ? 's-hi' : s >= 35 ? 's-mid' : 's-lo'
const tacticLabel = (t) => t.includes('-') ? `${t.split('-')[0]} · ${t.split('-').slice(1).join('-')}` : t

// MITRE ATT&CK technique (T) codes for the tooling hints emitted by
// analytics/behavioral/profiler.py — keep in sync with TOOLING_SIGNS there.
// None of these tools have an S (software) code in the ATT&CK catalog,
// so each maps to the technique it implements.
export const TOOLING_MITRE = {
  masscan: ['T1595.001', 'Active Scanning: Scanning IP Blocks'],
  hydra: ['T1110', 'Brute Force'],
  mirai: ['T1059.004', 'Command and Scripting Interpreter: Unix Shell'],
  cryptominer: ['T1496', 'Resource Hijacking'],
  wget_dropper: ['T1105', 'Ingress Tool Transfer'],
  shell_dropper: ['T1059.004', 'Command and Scripting Interpreter: Unix Shell'],
  recon: ['T1082', 'System Information Discovery'],
  persistence: ['T1098.004', 'Account Manipulation: SSH Authorized Keys'],
  privesc: ['T1548', 'Abuse Elevation Control Mechanism'],
  cleanup: ['T1070.003', 'Indicator Removal: Clear Command History'],
}
export const toolingTitle = (t) => TOOLING_MITRE[t] ? `${TOOLING_MITRE[t][0]} ${TOOLING_MITRE[t][1]}` : undefined

function uniqueVals(rows, fn) {
  return [...new Set(rows.map(fn).filter((v) => v != null && v !== '' && v !== '—'))].sort()
}

function ColFilter({ rows, accessor, value, onChange, multi }) {
  const opts = useMemo(() => {
    if (multi) return [...new Set(rows.flatMap(accessor))].filter(Boolean).sort()
    return uniqueVals(rows, accessor)
  }, [rows, accessor, multi])
  return (
    <th><select className="col-filter" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">all</option>
      {opts.map((v) => <option key={v} value={v}>{v}</option>)}
    </select></th>
  )
}

function matchFilter(cf, key, val) {
  if (!cf[key]) return true
  return String(val) === cf[key]
}

const SCAN_GROUPS = [['', 'None'], ['scan_type', 'Type'], ['as', 'AS']]

export function Scans({ onPick }) {
  const [rows, setRows] = useState([])
  const [window, setWindow] = useState('7d')
  const [groupBy, setGroupBy] = useState('')
  const [cf, setCf] = useState({})
  const setF = (k) => (v) => setCf((p) => ({ ...p, [k]: v }))

  useEffect(() => {
    let cancelled = false
    api.scans(window, groupBy).then((d) => { if (!cancelled) { setRows(d); setCf({}) } }).catch(() => {})
    return () => { cancelled = true }
  }, [window, groupBy])

  const filtered = useMemo(() => {
    if (groupBy) return rows
    return rows.filter((r) =>
      matchFilter(cf, 'date', fmtDate(r.ts)) &&
      matchFilter(cf, 'ip', r.src_ip) &&
      matchFilter(cf, 'country', r.country) &&
      matchFilter(cf, 'org', r.org || r.asn) &&
      matchFilter(cf, 'scan_type', r.scan_type) &&
      matchFilter(cf, 'ports', r.port_count))
  }, [rows, cf, groupBy])

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
        {filtered.length}
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
          <thead>
            <tr><th>time</th><th>ip</th><th>country</th><th>as</th><th>type</th><th>ports</th><th>port list</th></tr>
            <tr className="filter-row">
              <ColFilter rows={rows} accessor={(r) => fmtDate(r.ts)} value={cf.date || ''} onChange={setF('date')} />
              <ColFilter rows={rows} accessor={(r) => r.src_ip} value={cf.ip || ''} onChange={setF('ip')} />
              <ColFilter rows={rows} accessor={(r) => r.country} value={cf.country || ''} onChange={setF('country')} />
              <ColFilter rows={rows} accessor={(r) => r.org || r.asn} value={cf.org || ''} onChange={setF('org')} />
              <ColFilter rows={rows} accessor={(r) => r.scan_type} value={cf.scan_type || ''} onChange={setF('scan_type')} />
              <ColFilter rows={rows} accessor={(r) => r.port_count} value={cf.ports || ''} onChange={setF('ports')} />
              <th></th>
            </tr>
          </thead>
          <tbody>{filtered.map((r) => (
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

const ATTACK_GROUPS = [['', 'None'], ['service', 'Service'], ['as', 'AS']]

export function Attacks({ onPick }) {
  const [rows, setRows] = useState([])
  const [window, setWindow] = useState('24h')
  const [groupBy, setGroupBy] = useState('')
  const [cf, setCf] = useState({})
  const setF = (k) => (v) => setCf((p) => ({ ...p, [k]: v }))

  useEffect(() => {
    let cancelled = false
    api.attacks(window, groupBy).then((d) => { if (!cancelled) { setRows(d); setCf({}) } }).catch(() => {})
    return () => { cancelled = true }
  }, [window, groupBy])

  const filtered = useMemo(() => {
    if (groupBy) return rows
    return rows.filter((r) =>
      matchFilter(cf, 'date', fmtDate(r.ts)) &&
      matchFilter(cf, 'ip', r.src_ip) &&
      matchFilter(cf, 'country', r.country) &&
      matchFilter(cf, 'org', r.org || r.asn) &&
      matchFilter(cf, 'attack_type', r.attack_type) &&
      matchFilter(cf, 'service', r.service) &&
      matchFilter(cf, 'severity', r.severity))
  }, [rows, cf, groupBy])

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
        {filtered.length}
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
          <thead>
            <tr><th>last seen</th><th>ip</th><th>country</th><th>as</th><th>type</th><th>service</th><th>sev</th><th>count</th><th>evidence</th></tr>
            <tr className="filter-row">
              <ColFilter rows={rows} accessor={(r) => fmtDate(r.ts)} value={cf.date || ''} onChange={setF('date')} />
              <ColFilter rows={rows} accessor={(r) => r.src_ip} value={cf.ip || ''} onChange={setF('ip')} />
              <ColFilter rows={rows} accessor={(r) => r.country} value={cf.country || ''} onChange={setF('country')} />
              <ColFilter rows={rows} accessor={(r) => r.org || r.asn} value={cf.org || ''} onChange={setF('org')} />
              <ColFilter rows={rows} accessor={(r) => r.attack_type} value={cf.attack_type || ''} onChange={setF('attack_type')} />
              <ColFilter rows={rows} accessor={(r) => r.service} value={cf.service || ''} onChange={setF('service')} />
              <ColFilter rows={rows} accessor={(r) => r.severity} value={cf.severity || ''} onChange={setF('severity')} />
              <th></th>
              <th></th>
            </tr>
          </thead>
          <tbody>{filtered.map((r) => (
            <tr key={`${r.src_ip}|${r.attack_type}|${r.service}`}>
              <td className="muted" title={r.n > 1 ? `first: ${fmt(r.first_ts)}` : undefined}>{fmt(r.ts)}</td>
              <td className="ip" onClick={() => onPick(r.src_ip)}>{r.src_ip}</td>
              <td>{r.country || '—'}</td>
              <td className="muted org" title={r.org || r.asn || undefined}>{r.org || r.asn || '—'}</td>
              <td><span className="tag exploiter">{r.attack_type}</span></td>
              <td>{r.service || '—'}</td><td>{r.severity}</td>
              <td>{r.n > 1 ? `×${r.n}` : ''}</td>
              <td className="muted">{JSON.stringify(r.evidence).slice(0, 70)}</td></tr>
          ))}</tbody>
        </>)}
      </table></div></div>
  )
}

export function Behavior({ onPick }) {
  const [rows, setRows] = useState([])
  const [top3, setTop3] = useState([])
  const [window, setWindow] = useState('24h')
  const [cf, setCf] = useState({})
  const setF = (k) => (v) => setCf((p) => ({ ...p, [k]: v }))

  useEffect(() => {
    api.behavior('1y', 3).then(setTop3).catch(() => {})
    const id = setInterval(() => {
      api.behavior('1y', 3).then(setTop3).catch(() => {})
    }, 24 * 60 * 60 * 1000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    let cancelled = false
    api.behavior(window).then((d) => { if (!cancelled) { setRows(d); setCf({}) } }).catch(() => {})
    return () => { cancelled = true }
  }, [window])

  const filtered = useMemo(() => rows.filter((r) =>
    matchFilter(cf, 'ip', r.src_ip) &&
    matchFilter(cf, 'country', r.country) &&
    matchFilter(cf, 'org', r.org || r.asn) &&
    matchFilter(cf, 'class', r.classification) &&
    matchFilter(cf, 'score', Math.round(r.threat_score)) &&
    (!cf.tooling || (r.tooling_hints || []).includes(cf.tooling)) &&
    (!cf.tactic || (r.tactics || []).includes(cf.tactic))
  ), [rows, cf])

  return (
    <>
    {top3.length > 0 && (
      <div className="card" style={{ marginBottom: 18 }}>
        <h3><span>top threats · all time</span></h3>
        <div className="body"><table>
          <thead><tr><th>#</th><th>ip</th><th>country</th><th>as</th><th>class</th><th>score</th><th>logins</th><th>tactics</th></tr></thead>
          <tbody>{top3.map((r, i) => (
            <tr key={r.src_ip}>
              <td className="muted">{i + 1}</td>
              <td className="ip" onClick={() => onPick(r.src_ip)}>{r.src_ip}</td>
              <td>{r.country || '—'}</td>
              <td className="muted org" title={r.org || r.asn || undefined}>{r.org || r.asn || '—'}</td>
              <td><span className={`tag ${r.classification || 'prober'}`}>{r.classification || 'prober'}</span></td>
              <td className={`score ${scoreClass(r.threat_score)}`}>{Math.round(r.threat_score)}</td>
              <td>{r.login_attempts ?? 0}</td>
              <td><div className="tags">{(r.tactics || []).map((t) => <span key={t} className="tag tactic" title={t}>{tacticLabel(t)}</span>)}</div></td>
            </tr>
          ))}</tbody>
        </table></div>
      </div>
    )}
    <div className="card"><h3>
      <span>behavioral profiles</span>
      <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <select value={window} onChange={(e) => setWindow(e.target.value)}>
          {WINDOWS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        {filtered.length}
      </span>
    </h3>
      <div className="body"><table>
        <thead>
          <tr><th>ip</th><th>country</th><th>as</th><th>class</th><th>score</th><th>logins</th><th>tooling</th><th>tactics</th></tr>
          <tr className="filter-row">
            <ColFilter rows={rows} accessor={(r) => r.src_ip} value={cf.ip || ''} onChange={setF('ip')} />
            <ColFilter rows={rows} accessor={(r) => r.country} value={cf.country || ''} onChange={setF('country')} />
            <ColFilter rows={rows} accessor={(r) => r.org || r.asn} value={cf.org || ''} onChange={setF('org')} />
            <ColFilter rows={rows} accessor={(r) => r.classification} value={cf.class || ''} onChange={setF('class')} />
            <ColFilter rows={rows} accessor={(r) => Math.round(r.threat_score)} value={cf.score || ''} onChange={setF('score')} />
            <th></th>
            <ColFilter rows={rows} accessor={(r) => r.tooling_hints || []} value={cf.tooling || ''} onChange={setF('tooling')} multi />
            <ColFilter rows={rows} accessor={(r) => r.tactics || []} value={cf.tactic || ''} onChange={setF('tactic')} multi />
          </tr>
        </thead>
        <tbody>{filtered.map((r) => (
          <tr key={r.src_ip}>
            <td className="ip" onClick={() => onPick(r.src_ip)}>{r.src_ip}</td>
            <td>{r.country || '—'}</td>
            <td className="muted org" title={r.org || r.asn || undefined}>{r.org || r.asn || '—'}</td>
            <td><span className={`tag ${r.classification || 'prober'}`}>{r.classification || 'prober'}</span></td>
            <td className={`score ${scoreClass(r.threat_score)}`}>{Math.round(r.threat_score)}</td>
            <td>{r.login_attempts ?? 0}</td>
            <td>
              <div className="tags">
                {(r.tooling_hints || []).length
                  ? (r.tooling_hints || []).map((t) => <span key={t} className="tag tooling" title={toolingTitle(t)}>{t}</span>)
                  : <span className="muted">—</span>}
              </div>
            </td>
            <td>
              <div className="tags">
                {(r.tactics || []).length
                  ? (r.tactics || []).map((t) => <span key={t} className="tag tactic" title={t}>{tacticLabel(t)}</span>)
                  : <span className="muted">—</span>}
              </div>
            </td>
          </tr>
        ))}</tbody></table></div></div>
    </>
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
