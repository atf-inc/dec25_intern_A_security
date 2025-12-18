'use client'

import { useState } from 'react'

export default function DeserializationPage() {
  const [data, setData] = useState('{"name": "John", "age": 30}')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const testDeserialization = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/vulnerable/deserialization', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: data
      })
      const responseData = await response.json()
      setResult(responseData)
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  const loadPayload = () => {
    setData('{"name": "test", "__proto__": {"isAdmin": true}}')
  }

  return (
    <div className="container">
      <h1>Insecure Deserialization Vulnerability</h1>
      
      <div className="warning" style={{ marginBottom: '20px' }}>
        <strong>⚠️ WARNING:</strong> This endpoint uses eval() which can execute arbitrary code!
      </div>

      <div className="info-box">
        <strong>Test Deserialization Attacks:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>Prototype pollution: <code>{"__proto__": {"isAdmin": true}}</code></li>
          <li>Code injection: <code>{"name": "test", "exec": "system('rm -rf /')"}</code></li>
        </ul>
      </div>

      <div className="form-group">
        <label>Data to deserialize (Vulnerable):</label>
        <textarea
          value={data}
          onChange={(e) => setData(e.target.value)}
          rows={6}
          style={{ fontFamily: 'monospace' }}
        />
      </div>

      <button onClick={testDeserialization} disabled={loading}>
        {loading ? 'Deserializing...' : 'Deserialize Data'}
      </button>
      <button onClick={loadPayload} style={{ marginLeft: '10px' }}>
        Load Payload
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

