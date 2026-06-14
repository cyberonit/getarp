import React, { useState } from 'react'
import { api } from './lib/api.js'
import Dashboard from './components/Dashboard.jsx'
import Detail from './components/Detail.jsx'
import { Scans, Attacks, Behavior, Reports } from './components/Lists.jsx'
import { Login, Settings } from './components/Admin.jsx'

const NAV = [
  ['overview', 'OVERVIEW'],
  ['scans', 'SCANS'],
  ['attacks', 'ATTACKS'],
  ['behavior', 'BEHAVIOR'],
  ['reports', 'REPORTS'],
  ['settings', 'SETTINGS'],
]

export default function App() {
  const [view, setView] = useState('overview')
  const [pick, setPick] = useState(null)
  const [authed, setAuthed] = useState(api.isAuthed())

  const needsAuth = view === 'settings'
  if (needsAuth && !authed) return <Login onDone={() => setAuthed(true)} />

  return (
    <div className="shell">
      <nav className="rail">
        <div className="brand"><b>getarp</b> grid<small>deception intel</small></div>
        <div style={{ height: 14 }} />
        {NAV.map(([k, label]) => (
          <div key={k} className={`nav-item ${view === k ? 'active' : ''}`}
            onClick={() => setView(k)}>
            <span>{label}</span>{k === 'settings' && <span>🔒</span>}
          </div>
        ))}
        <div className="spacer" />
        {authed && (
          <div className="nav-item" onClick={() => { api.logout(); setAuthed(false); setView('overview') }}>
            <span>SIGN OUT</span></div>
        )}
        <div className="muted" style={{ fontSize: 10, marginTop: 10 }}>getarp.net · v0.1</div>
      </nav>

      <main className="main">
        {view === 'overview' && <Dashboard onPick={setPick} />}
        {view === 'scans' && <Scans onPick={setPick} />}
        {view === 'attacks' && <Attacks onPick={setPick} />}
        {view === 'behavior' && <Behavior onPick={setPick} />}
        {view === 'reports' && <Reports />}
        {view === 'settings' && <Settings />}
      </main>

      {pick && <Detail ip={pick} onClose={() => setPick(null)} />}
    </div>
  )
}
