import React, { useEffect, useRef, useState } from 'react'
import { api } from '../lib/api.js'

const scoreClass = (s) => s >= 70 ? 's-hi' : s >= 35 ? 's-mid' : 's-lo'

const AS_WINDOWS = [['1h', '1h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']]

export default function Dashboard({ onPick }) {
  const [status, setStatus] = useState({})
  const [ips, setIps] = useState([])
  const [feed, setFeed] = useState([])
  const [topAS, setTopAS] = useState([])
  const [asWindow, setAsWindow] = useState('1h')
  const wsRef = useRef(null)

  async function refresh() {
    try { setStatus(await api.status()) } catch {}
    try { setIps(await api.ips()) } catch {}
  }

  useEffect(() => {
    refresh()
    const poll = setInterval(refresh, 300000) // 5-min fallback poll
    const ws = api.liveSocket((m) => {
      if (m.type === 'status') setStatus((s) => ({ ...s, ...m }))
      else setFeed((f) => [{ ...m, at: new Date() }, ...f].slice(0, 40))
    })
    wsRef.current = ws
    return () => { clearInterval(poll); ws.close() }
  }, [])

  useEffect(() => {
    api.topAS(asWindow).then(setTopAS).catch(() => setTopAS([]))
  }, [asWindow])

  const level = status.threat_level || 'low'
  const countries = status.top_countries || []
  const maxC = Math.max(1, ...countries.map((c) => c.n))
  const ipInfo = Object.fromEntries(ips.map((ip) => [ip.src_ip, ip]))

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
          <div className="v" style={{ color: 'var(--text)' }}>{ips.length}</div><div className="spark" /></div>
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

        <div className="card geo">
          <h3><span>origin · last hour</span><span>top countries</span></h3>
          <div className="body">
            {countries.length === 0 && <div className="muted">no enriched origins yet</div>}
            {countries.map((c) => (
              <div className="row" key={c.country}>
                <span className="cc">{c.country}</span>
                <span className="bar" style={{ width: `${(c.n / maxC) * 200}px` }} />
                <span className="n">{c.n}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h3><span>top AS</span>
            <span>
              {AS_WINDOWS.map(([k, label]) => (
                <a key={k} onClick={() => setAsWindow(k)}
                  style={{ marginLeft: 8, fontWeight: k === asWindow ? 'bold' : 'normal' }}>{label}</a>
              ))}
            </span>
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
    </>
  )
}
