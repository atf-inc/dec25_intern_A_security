'use client'

import { useState } from 'react'

export default function CommandInjectionPage() {
  const [host, setHost] = useState('localhost')
  const [command, setCommand] = useState('')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const testPing = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/vulnerable/command-injection?host=${encodeURIComponent(host)}`)
      const data = await response.json()
      setResult(data)
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  const testCommand = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/vulnerable/command-injection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command })
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
      <h1>Command Injection Vulnerability</h1>
      
      <div className="warning" style={{ marginBottom: '20px' }}>
        <strong>⚠️ WARNING:</strong> This endpoint executes system commands. Use with caution!
      </div>

      <div className="info-box">
        <strong>Test Command Injection:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>Windows: <code>localhost &amp;&amp; dir</code></li>
          <li>Linux: <code>localhost; ls -la</code></li>
          <li>Chain commands: <code>localhost | cat /etc/passwd</code></li>
        </ul>
      </div>

      <h2>1. Ping Command (Vulnerable)</h2>
      <div className="form-group">
        <label>Host to ping:</label>
        <input
          type="text"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="localhost; ls"
        />
      </div>
      <button onClick={testPing} disabled={loading}>
        {loading ? 'Executing...' : 'Ping Host'}
      </button>

      <h2>2. Direct Command Execution (Very Vulnerable)</h2>
      <div className="form-group">
        <label>Command to execute:</label>
        <input
          type="text"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          placeholder="whoami"
        />
      </div>
      <button onClick={testCommand} disabled={loading}>
        {loading ? 'Executing...' : 'Execute Command'}
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
              {result.command && (
                <div className="code-block">
                  <strong>Command:</strong> {result.command}
                </div>
              )}
              {result.output && (
                <div className="code-block">
                  <strong>Output:</strong>
                  <pre style={{ whiteSpace: 'pre-wrap' }}>{result.output}</pre>
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

