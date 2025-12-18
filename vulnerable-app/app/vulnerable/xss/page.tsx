'use client'

import { useState } from 'react'

export default function XSSPage() {
  const [name, setName] = useState('')
  const [comment, setComment] = useState('')
  const [user, setUser] = useState('')
  const [result, setResult] = useState<any>(null)
  const [comments, setComments] = useState<any[]>([])
  const [loading, setLoading] = useState(false)

  const testReflectedXSS = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/vulnerable/xss?name=${encodeURIComponent(name)}`)
      const data = await response.json()
      setResult(data)
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  const testStoredXSS = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/vulnerable/xss', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ comment, user })
      })
      const data = await response.json()
      setResult(data)
      setComments(data.allComments || [])
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  const testDOMXSS = () => {
    // DOM-based XSS example
    const urlParams = new URLSearchParams(window.location.search)
    const input = urlParams.get('input') || ''
    setResult({
      type: 'DOM-based XSS',
      input: input,
      rendered: input, // This would be rendered in HTML - vulnerable
      warning: 'Try: ?input=<img src=x onerror=alert("XSS")>'
    })
  }

  return (
    <div className="container">
      <h1>XSS (Cross-Site Scripting) Vulnerabilities</h1>
      
      <div className="info-box">
        <strong>Test XSS Attacks:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>Reflected XSS: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
          <li>Stored XSS: <code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
          <li>DOM XSS: <code>&lt;svg onload=alert('XSS')&gt;</code></li>
        </ul>
      </div>

      <h2>1. Reflected XSS</h2>
      <div className="form-group">
        <label>Name (Vulnerable to Reflected XSS):</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="<script>alert('XSS')</script>"
        />
      </div>
      <button onClick={testReflectedXSS} disabled={loading}>
        {loading ? 'Testing...' : 'Test Reflected XSS'}
      </button>

      <h2>2. Stored XSS</h2>
      <div className="form-group">
        <label>User:</label>
        <input
          type="text"
          value={user}
          onChange={(e) => setUser(e.target.value)}
          placeholder="Username"
        />
      </div>
      <div className="form-group">
        <label>Comment (Vulnerable to Stored XSS):</label>
        <textarea
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder="<img src=x onerror=alert('XSS')>"
          rows={4}
        />
      </div>
      <button onClick={testStoredXSS} disabled={loading}>
        {loading ? 'Testing...' : 'Submit Comment (Stored XSS)'}
      </button>

      {comments.length > 0 && (
        <div className="result" style={{ marginTop: '20px' }}>
          <h3>Stored Comments (Vulnerable to XSS):</h3>
          {comments.map((c: any) => (
            <div key={c.id} style={{ margin: '10px 0', padding: '10px', background: '#f5f5f5' }}>
              <strong>{c.user}:</strong>
              <div dangerouslySetInnerHTML={{ __html: c.comment }} />
            </div>
          ))}
        </div>
      )}

      <h2>3. DOM-based XSS</h2>
      <button onClick={testDOMXSS}>
        Test DOM XSS (Check URL parameters)
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

