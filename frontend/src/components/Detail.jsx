import React, { useEffect, useState } from 'react'
import { api } from '../lib/api.js'

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

        <h3 style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)' }}>
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
