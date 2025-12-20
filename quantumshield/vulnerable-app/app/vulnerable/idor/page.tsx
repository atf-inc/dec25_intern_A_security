'use client'

import { useState } from 'react'

export default function IDORPage() {
  const [userId, setUserId] = useState('1')
  const [balance, setBalance] = useState('1000')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const getUser = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/vulnerable/idor?id=${userId}`)
      const data = await response.json()
      setResult(data)
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  const updateBalance = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/vulnerable/idor', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: parseInt(userId), balance: parseFloat(balance) })
      })
      const data = await response.json()
      setResult(data)
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container">
      <h1>IDOR (Insecure Direct Object Reference) Vulnerability</h1>
      
      <div className="info-box">
        <strong>Test IDOR Attacks:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>Access other users: Try different user IDs (1, 2, 3)</li>
          <li>Modify other users' data: Change balance without authorization</li>
          <li>Enumerate users: Try sequential IDs</li>
        </ul>
      </div>

      <h2>1. Get User (No Authorization Check)</h2>
      <div className="form-group">
        <label>User ID:</label>
        <input
          type="number"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="1"
        />
      </div>
      <button onClick={getUser} disabled={loading}>
        {loading ? 'Loading...' : 'Get User'}
      </button>

      <h2>2. Update Balance (No Authorization Check)</h2>
      <div className="form-group">
        <label>User ID:</label>
        <input
          type="number"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label>New Balance:</label>
        <input
          type="number"
          value={balance}
          onChange={(e) => setBalance(e.target.value)}
        />
      </div>
      <button onClick={updateBalance} disabled={loading}>
        {loading ? 'Updating...' : 'Update Balance'}
      </button>

      {result && (
        <div className={`result ${result.error || result.blocked ? 'error' : 'success'}`}>
          <h3>Result:</h3>
          {result.blocked ? (
            <div style={{ 
              padding: '1.5rem', 
              background: 'linear-gradient(135deg, #fee 0%, #fdd 100%)', 
              border: '3px solid #f00', 
              borderRadius: '12px',
              fontSize: '1.2rem',
              textAlign: 'center',
              color: '#c00',
              boxShadow: '0 4px 6px rgba(255, 0, 0, 0.1)'
            }}>
              <div style={{ fontSize: '3rem', marginBottom: '0.5rem' }}>🚫</div>
              <strong style={{ fontSize: '1.3rem' }}>
                {result.message || 'Request blocked by firewall'}
              </strong>
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

