'use client'

import { useState } from 'react'

export default function SQLInjectionPage() {
  const [userId, setUserId] = useState('1')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const testSQLInjection = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/vulnerable/sql-injection?id=${encodeURIComponent(userId)}`)
      const data = await response.json()
      
      // Check if response indicates blocking (403 or blocked flag)
      if (response.status === 403 || data.blocked) {
        setResult({ blocked: true, message: data.message || 'Request blocked by firewall' })
      } else {
        setResult(data)
      }
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  const testLogin = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/vulnerable/sql-injection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: "admin' OR '1'='1",
          password: "anything' OR '1'='1"
        })
      })
      const data = await response.json()
      
      // Check if response indicates blocking (403 or blocked flag)
      if (response.status === 403 || data.blocked) {
        setResult({ blocked: true, message: data.message || 'Request blocked by firewall' })
      } else {
        setResult(data)
      }
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container">
      <h1>SQL Injection Vulnerability</h1>
      
      <div className="info-box">
        <strong>Test SQL Injection Attacks:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>Try: <code>1 OR 1=1</code> to get all users</li>
          <li>Try: <code>1 UNION SELECT null, null, null, null</code></li>
          <li>Try: <code>1'; DROP TABLE users; --</code></li>
          <li>Try username: <code>john_doe</code> or <code>admin</code></li>
          <li>Try username injection: <code>john_doe' OR '1'='1</code></li>
        </ul>
      </div>

      <div className="form-group">
        <label>User ID or Username (Vulnerable to SQL Injection):</label>
        <input
          type="text"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="1 OR 1=1 or john_doe"
        />
        <div style={{ marginTop: '0.5rem', fontSize: '0.9rem', color: '#666' }}>
          You can enter a numeric ID (1-20) or a username (john_doe, jane_smith, etc.)
        </div>
      </div>

      <button onClick={testSQLInjection} disabled={loading}>
        {loading ? 'Testing...' : 'Test SQL Injection'}
      </button>

      <button onClick={testLogin} disabled={loading} style={{ marginLeft: '10px' }}>
        {loading ? 'Testing...' : 'Test Login Bypass'}
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
              background: result.success === false && result.message?.includes('not found') 
                ? '#fff3cd' 
                : '#fee', 
              border: `1px solid ${result.success === false && result.message?.includes('not found') ? '#ffc107' : '#f00'}`, 
              borderRadius: '8px',
              color: result.success === false && result.message?.includes('not found') ? '#856404' : '#c00'
            }}>
              <strong>{result.success === false && result.message?.includes('not found') ? '⚠️ ' : 'Error: '}</strong>
              {result.message || result.error}
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

