import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../lib/api.js'

const scoreClass = (s) => s >= 70 ? 's-hi' : s >= 35 ? 's-mid' : 's-lo'

const AS_WINDOWS = [['1h', '1h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']]

const tacticLabel = (t) => t.includes('-') ? t.split('-').slice(1).join('-') : t

export default function Dashboard({ onPick }) {
  const [status, setStatus] = useState({})
  const [ips, setIps] = useState([])
  const [feed, setFeed] = useState([])
  const [topAS, setTopAS] = useState([])
  const [asWindow, setAsWindow] = useState('1h')
  const [countries, setCountries] = useState([])
  const [cWindow, setCWindow] = useState('1h')
  const [behavior, setBehavior] = useState([])
  const wsRef = useRef(null)

  async function refresh() {
    try { setStatus(await api.status()) } catch {}
    try { setIps(await api.ips()) } catch {}
    try { setBehavior(await api.behavior('24h')) } catch {}
  }

  useEffect(() => {
    refresh()
    const poll = setInterval(refresh, 300000)
    let ws = null
    api.liveSocket((m) => {
      if (m.type === 'status') setStatus((s) => ({ ...s, ...m }))
      else setFeed((f) => [{ ...m, at: new Date() }, ...f].slice(0, 40))
    }).then((s) => { ws = s; wsRef.current = s }).catch(() => {})
    return () => { clearInterval(poll); if (ws) ws.close() }
  }, [])

  useEffect(() => {
    api.topAS(asWindow).then(setTopAS).catch(() => setTopAS([]))
  }, [asWindow])

  useEffect(() => {
    api.topCountries(cWindow).then(setCountries).catch(() => setCountries([]))
  }, [cWindow])

  const level = status.threat_level || 'low'
  const maxC = Math.max(1, ...countries.map((c) => c.n))
  const ipInfo = useMemo(
    () => Object.fromEntries(ips.map((ip) => [ip.src_ip, ip])),
    [ips]
  )

  return (
    <>
      <div className="strip">
        <div className="stat hot">
          <div className="k">live attackers · 5m</div>
          <div className="v">{status.live_attackers ?? '—'}</div><div className="spark" /></div>
        <div className="stat ok">
          <div className="k">new ips · 5m</div>
          <div className="v">{status.new_ips ?? '—'}</div><div className="spark" /></div>
        <div className="stat warn">
          <div className="k">events / min</div>
          <div className="v">{status.events_per_min != null ? Math.round(status.events_per_min) : '—'}</div><div className="spark" /></div>
        <div className="stat">
          <div className="k">tracked hosts</div>
          <div className="v" style={{ color: 'var(--text)' }}>{status.tracked_hosts ?? '—'}</div><div className="spark" /></div>
      </div>

      <div className="threatbar">
        <span className={`dot ${level}`} />
        <span className="lvl">threat level — {level}</span>
        <span className="meta">snapshot cadence 5 min · live feed via websocket</span>
      </div>

      <div className="card">
        <h3><span>live feed</span><span>realtime</span></h3>
        <div className="body feed">
          {feed.length === 0 && <div className="muted">waiting for activity…</div>}
          {feed.map((e, i) => {
            const info = ipInfo[e.src_ip]
            return (
              <div key={i} className={`e ${e.type}`}>
                <span className="t">{e.at.toLocaleTimeString()}</span>
                <span className="lbl">{e.type === 'attack' ? '⚠' : '⦿'} {e.label}</span>
                <span className="ip" onClick={() => onPick(e.src_ip)}>{e.src_ip}</span>
                <span className="muted">{info?.country || '—'}</span>
                <span className="muted">{info?.org || info?.asn || '—'}</span>
              </div>
            )
          })}
        </div>
      </div>

      <div className="card" style={{ marginTop: 18 }}>
        <h3><span>behavioral threats</span><span>24 h · by profile score</span></h3>
        <div className="body">
          {behavior.length === 0
            ? <div className="muted">no behavioral profiles in window</div>
            : <table>
                <thead><tr><th>ip</th><th>class</th><th>score</th><th>logins</th><th>tooling</th><th>tactics</th><th>country</th></tr></thead>
                <tbody>{behavior.slice(0, 10).map((b) => (
                  <tr key={b.src_ip}>
                    <td className="ip" onClick={() => onPick(b.src_ip)}>{b.src_ip}</td>
                    <td><span className={`tag ${b.classification || 'prober'}`}>{b.classification || 'prober'}</span></td>
                    <td className={`score ${scoreClass(b.threat_score)}`}>{Math.round(b.threat_score)}</td>
                    <td>{b.login_attempts ?? 0}</td>
                    <td>
                      <div className="tags">
                        {(b.tooling_hints || []).length
                          ? (b.tooling_hints || []).map((t) => <span key={t} className="tag tooling">{t}</span>)
                          : <span className="muted">—</span>}
                      </div>
                    </td>
                    <td>
                      <div className="tags">
                        {(b.tactics || []).length
                          ? (b.tactics || []).map((t) => <span key={t} className="tag tactic" title={t}>{tacticLabel(t)}</span>)
                          : <span className="muted">—</span>}
                      </div>
                    </td>
                    <td>{b.country || '—'}</td>
                  </tr>
                ))}</tbody>
              </table>
          }
        </div>
      </div>

      <div className="grid2" style={{ marginTop: 18 }}>
        <div className="card">
          <h3><span>top attackers</span><span>by threat score</span></h3>
          <div className="body">
            <table>
              <thead><tr><th>ip</th><th>score</th><th>class</th><th>country</th><th>as</th>
                <th>svcs</th><th>events</th></tr></thead>
              <tbody>
                {ips.slice(0, 18).map((ip) => (
                  <tr key={ip.src_ip}>
                    <td className="ip" onClick={() => onPick(ip.src_ip)}>{ip.src_ip}</td>
                    <td className={`score ${scoreClass(ip.threat_score)}`}>{Math.round(ip.threat_score)}</td>
                    <td><span className={`tag ${ip.classification}`}>{ip.classification}</span></td>
                    <td>{ip.country || '—'}</td>
                    <td className="muted">{ip.org || ip.asn || '—'}</td>
                    <td>{(ip.services_hit || []).length}</td>
                    <td>{ip.event_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div>
          <div className="card geo">
            <h3><span>top countries</span>
              <select value={cWindow} onChange={(e) => setCWindow(e.target.value)}>
                {AS_WINDOWS.map(([k, label]) => (
                  <option key={k} value={k}>{label}</option>
                ))}
              </select>
            </h3>
            <div className="body">
              {countries.length === 0 && <div className="muted">no enriched origins yet</div>}
              {countries.map((c) => (
                <div className="row" key={c.country}>
                  <span className="cc">{c.country}</span>
                  <span className="bar" style={{ width: `${(c.n / maxC) * 100}px` }} />
                  <span className="n">{c.n}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card" style={{ marginTop: 18 }}>
            <h3><span>top AS</span>
              <select value={asWindow} onChange={(e) => setAsWindow(e.target.value)}>
                {AS_WINDOWS.map(([k, label]) => (
                  <option key={k} value={k}>{label}</option>
                ))}
              </select>
            </h3>
            <div className="body">
              {topAS.length === 0 && <div className="muted">no enriched events in this window</div>}
              <table><thead><tr><th>asn</th><th>org</th><th>events</th></tr></thead>
                <tbody>{topAS.map((a) => (
                  <tr key={a.asn}><td>{a.asn}</td><td className="muted">{a.org || '—'}</td><td>{a.n}</td></tr>
                ))}</tbody></table>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
