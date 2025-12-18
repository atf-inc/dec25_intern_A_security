'use client'

import { useState } from 'react'

export default function AuthBypassPage() {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin123')
  const [token, setToken] = useState('')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const login = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/vulnerable/auth-bypass', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      const data = await response.json()
      setResult(data)
      if (data.token) {
        setToken(data.token)
      }
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  const validateToken = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/vulnerable/auth-bypass?token=${encodeURIComponent(token)}`)
      const data = await response.json()
      setResult(data)
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  const decodeToken = () => {
    try {
      const decoded = atob(token)
      setResult({
        type: 'Token Decoded',
        token: token,
        decoded: decoded,
        warning: 'Token is easily decodable - no encryption!'
      })
    } catch (e) {
      setResult({ error: 'Invalid token format' })
    }
  }

  return (
    <div className="container">
      <h1>Authentication Bypass Vulnerability</h1>
      
      <div className="info-box">
        <strong>Test Authentication Bypass:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>Weak passwords: Try common passwords</li>
          <li>Token manipulation: Decode and modify tokens</li>
          <li>Session fixation: Reuse tokens</li>
        </ul>
      </div>

      <h2>1. Login (Weak Authentication)</h2>
      <div className="form-group">
        <label>Username:</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label>Password:</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      <button onClick={login} disabled={loading}>
        {loading ? 'Logging in...' : 'Login'}
      </button>

      <h2>2. Token Validation (Weak)</h2>
      <div className="form-group">
        <label>Token:</label>
        <input
          type="text"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="Base64 encoded token"
        />
      </div>
      <button onClick={validateToken} disabled={loading || !token}>
        {loading ? 'Validating...' : 'Validate Token'}
      </button>
      <button onClick={decodeToken} style={{ marginLeft: '10px' }}>
        Decode Token
      </button>

      {result && (
        <div className={`result ${result.error || result.blocked ? 'error' : 'success'}`}>
          <h3>Result:</h3>
          {result.blocked ? (
            <div style={{ 
              padding: '1.5rem', 
              background: '#fee', 
              border: '2px solid #f00', 
              borderRadius: '8px',
              fontSize: '1.1rem',
              textAlign: 'center',
              color: '#c00'
            }}>
              <strong>🚫 {result.message || 'Request blocked by firewall'}</strong>
            </div>
          ) : result.error ? (
            <div style={{ 
              padding: '1rem', 
              background: '#fee', 
              border: '1px solid #f00', 
              borderRadius: '8px',
              color: '#c00'
            }}>
              <strong>Error:</strong> {result.error}
            </div>
          ) : (
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {JSON.stringify(result, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

