'use client'

import { useState } from 'react'

export default function PathTraversalPage() {
  const [file, setFile] = useState('test.txt')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const testPathTraversal = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/vulnerable/path-traversal?file=${encodeURIComponent(file)}`)
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
      <h1>Path Traversal Vulnerability</h1>
      
      <div className="info-box">
        <strong>Test Path Traversal:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>Linux: <code>../../../etc/passwd</code></li>
          <li>Windows: <code>..\\..\\..\\windows\\system32\\config\\sam</code></li>
          <li>Relative: <code>../../package.json</code></li>
        </ul>
      </div>

      <div className="form-group">
        <label>File to read (Vulnerable to Path Traversal):</label>
        <input
          type="text"
          value={file}
          onChange={(e) => setFile(e.target.value)}
          placeholder="../../../etc/passwd"
        />
      </div>

      <button onClick={testPathTraversal} disabled={loading}>
        {loading ? 'Reading...' : 'Read File'}
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
                  <strong>File Content:</strong>
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

