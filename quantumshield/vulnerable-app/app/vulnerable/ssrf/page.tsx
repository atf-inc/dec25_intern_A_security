'use client'

import { useState } from 'react'

export default function SSRFPage() {
  const [url, setUrl] = useState('https://example.com')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const testSSRF = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/vulnerable/ssrf?url=${encodeURIComponent(url)}`)
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
      <h1>SSRF (Server-Side Request Forgery) Vulnerability</h1>
      
      <div className="warning" style={{ marginBottom: '20px' }}>
        <strong>⚠️ WARNING:</strong> This endpoint makes server-side requests without validation!
      </div>

      <div className="info-box">
        <strong>Test SSRF Attacks:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>Internal services: <code>http://localhost:22</code></li>
          <li>File protocol: <code>file:///etc/passwd</code></li>
          <li>Metadata services: <code>http://169.254.169.254/latest/meta-data/</code></li>
        </ul>
      </div>

      <div className="form-group">
        <label>URL to fetch (Vulnerable to SSRF):</label>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="http://localhost:22"
          style={{ width: '100%' }}
        />
      </div>

      <button onClick={testSSRF} disabled={loading}>
        {loading ? 'Fetching...' : 'Fetch URL'}
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
            <>
              {result.content && (
                <div className="code-block">
                  <strong>Response Content:</strong>
                  <pre style={{ whiteSpace: 'pre-wrap' }}>{result.content}</pre>
                </div>
              )}
              <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                {JSON.stringify(result, null, 2)}
              </pre>
            </>
          )}
        </div>
      )}
    </div>
  )
}

