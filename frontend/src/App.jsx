import React, { Component, useState } from 'react'
import { api } from './lib/api.js'
import Dashboard from './components/Dashboard.jsx'
import Detail from './components/Detail.jsx'
import { Scans, Attacks, Behavior, Reports } from './components/Lists.jsx'
import { Login, Settings, Docs } from './components/Admin.jsx'

const NAV = [
  ['overview', 'OVERVIEW'],
  ['scans', 'SCANS'],
  ['attacks', 'ATTACKS'],
  ['behavior', 'BEHAVIOR'],
  ['reports', 'REPORTS'],
  ['docs', 'DOCS'],
  ['contact', 'CONTACT'],
  ['settings', 'SETTINGS'],
]

function Contact() {
  return (
    <div className="card"><h3><span>contact</span></h3>
      <div className="body">
        <p>For inquiries, reach us at <a href="mailto:office@cyberonit.com">office@cyberonit.com</a></p>
      </div></div>
  )
}

class ErrorBoundary extends Component {
  state = { error: null, info: null }
  static getDerivedStateFromError(error) { return { error } }
  componentDidCatch(error, info) { this.setState({ info }) }
  render() {
    if (this.state.error) return (
      <div style={{ padding: 40, color: '#f87171', fontFamily: 'monospace', whiteSpace: 'pre-wrap', fontSize: 12 }}>
        <h2>something broke</h2>
        <pre>{this.state.error.message}</pre>
        <pre>{this.state.error.stack}</pre>
        <pre>{this.state.info?.componentStack}</pre>
        <button onClick={() => this.setState({ error: null, info: null })}>retry</button>
      </div>
    )
    return this.props.children
  }
}

const AUTH_VIEWS = ['settings']

export default function App() {
  const [view, setView] = useState('overview')
  const [pick, setPick] = useState(null)
  const [authed, setAuthed] = useState(api.isAuthed())

  const needsAuth = AUTH_VIEWS.includes(view)
  if (needsAuth && !authed) return <Login onDone={() => setAuthed(true)} />

  return (
    <ErrorBoundary>
    <div className="shell">
      <nav className="rail">
        <div className="brand"><b>getarp</b> grid<small>deception intel</small></div>
        <div style={{ height: 14 }} />
        {NAV.map(([k, label]) => (
          <div key={k} className={`nav-item ${view === k ? 'active' : ''}`}
            onClick={() => setView(k)}>
            <span>{label}</span>{AUTH_VIEWS.includes(k) && <span>🔒</span>}
          </div>
        ))}
        <div className="spacer" />
        {authed && (
          <div className="nav-item" onClick={() => { api.logout().then(() => { setAuthed(false); setView('overview') }) }}>
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
        {view === 'contact' && <Contact />}
        {view === 'settings' && <Settings />}
        {view === 'docs' && <Docs />}
      </main>

      {pick && <Detail ip={pick} onClose={() => setPick(null)} />}
    </div>
    </ErrorBoundary>
  )
}
