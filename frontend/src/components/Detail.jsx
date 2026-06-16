import React, { useEffect, useState } from 'react'
import { api } from '../lib/api.js'

const REP_COLOR = { malicious: '#f87171', suspicious: '#fb923c', clean: '#4ade80', unknown: '#6b7280' }

function IntelSources({ raw }) {
  if (!raw || typeof raw !== 'object') return null
  const providers = Object.entries(raw).filter(([, v]) => v && !v.error)
  const errors = Object.entries(raw).filter(([, v]) => v && v.error)
  if (!providers.length && !errors.length) return null
  return (
    <>
      <h3 style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 18 }}>
        INTEL SOURCES</h3>
      <table><tbody>
        {providers.map(([name, data]) => {
          const rep = data.reputation || data.web_score_name || data.classification || '—'
          const score = data.abuseConfidenceScore ?? data.last_analysis_stats?.malicious ?? null
          const scoreLabel = score !== null ? ` · ${score}${data.abuseConfidenceScore !== undefined ? '%' : ' detections'}` : ''
          const org = data.as_owner || data.isp || data.name || ''
          return (
            <tr key={name}>
              <td style={{ color: 'var(--text-dim)', width: 90 }}>{name}</td>
              <td style={{ color: REP_COLOR[rep] || REP_COLOR.unknown }}>{rep}</td>
              <td className="muted">{scoreLabel}</td>
              <td className="muted" style={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis' }}>{org}</td>
            </tr>
          )
        })}
        {errors.map(([name, data]) => (
          <tr key={name}>
            <td style={{ color: 'var(--text-dim)', width: 90 }}>{name}</td>
            <td className="muted" colSpan={3}>error: {data.error}</td>
          </tr>
        ))}
      </tbody></table>
    </>
  )
}

export default function Detail({ ip, onClose }) {
  const [d, setD] = useState(null)
  useEffect(() => { api.ipDetail(ip).then(setD).catch(() => setD({ error: true })) }, [ip])
  if (!d) return null
  const info = d.info || {}
  const prof = d.profile || {}
  return (
    <>
      <div className="drawer-bg" onClick={onClose} />
      <div className="drawer">
        <span className="close" onClick={onClose}>[ close ]</span>
        <h2>{ip}</h2>
        <div className="muted">{info.org || '—'} · {info.country || '??'} · {info.asn || ''}</div>
        <div className="kv">
          <span className="key">threat score</span><span>{info.threat_score ?? '—'}</span>
          <span className="key">classification</span><span>{info.classification || '—'}</span>
          <span className="key">reputation</span><span>{info.reputation || 'unknown'}</span>
          <span className="key">events</span><span>{info.event_count ?? 0}</span>
          <span className="key">services hit</span><span>{(info.services_hit || []).join(', ')}</span>
          <span className="key">ports hit</span><span>{(info.ports_hit || []).join(', ')}</span>
          <span className="key">tooling</span><span>{(prof.tooling_hints || []).join(', ') || '—'}</span>
          <span className="key">tactics</span><span>{(prof.tactics || []).join(', ') || '—'}</span>
        </div>

        <IntelSources raw={info.enrichment_raw} />

        <h3 style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 18 }}>
          ATTACKS ({d.attacks.length})</h3>
        <table><tbody>
          {d.attacks.slice(0, 12).map((a) => (
            <tr key={a.id}><td>{a.attack_type}</td><td>{a.service || ''}</td>
              <td className="muted">{new Date(a.ts).toLocaleString()}</td></tr>
          ))}
        </tbody></table>

        <h3 style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 18 }}>
          RECENT EVENTS</h3>
        <table><tbody>
          {d.events.slice(0, 20).map((e, i) => (
            <tr key={i}><td>{e.event_type}</td><td>{e.service}</td>
              <td>{e.command || e.username || e.signature || ''}</td></tr>
          ))}
        </tbody></table>
      </div>
    </>
  )
}
