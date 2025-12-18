'use client'

import { useState } from 'react'

export default function OrdersPage() {
  const [trackingUrl, setTrackingUrl] = useState('https://api.shipping.com/track/12345')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const trackOrder = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/orders/track?url=${encodeURIComponent(trackingUrl)}`)
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
      <h1>Order Tracking</h1>
      
      <div className="alert alert-warning">
        <strong>⚠️ Vulnerability:</strong> Order tracking is vulnerable to SSRF attacks.
        <ul style={{ marginTop: '0.5rem', marginLeft: '1.5rem' }}>
          <li>Try: <code>http://localhost:22</code> (SSH port)</li>
          <li>Try: <code>file:///etc/passwd</code> (file protocol)</li>
          <li>Try: <code>http://169.254.169.254/latest/meta-data/</code> (cloud metadata)</li>
        </ul>
      </div>

      <div style={{ background: 'white', padding: '2rem', borderRadius: '10px', boxShadow: '0 2px 10px rgba(0,0,0,0.1)' }}>
        <div className="form-group">
          <label>Tracking URL (Vulnerable to SSRF):</label>
          <input
            type="text"
            value={trackingUrl}
            onChange={(e) => setTrackingUrl(e.target.value)}
            placeholder="https://api.shipping.com/track/12345"
          />
        </div>
        <button onClick={trackOrder} className="btn btn-primary" disabled={loading}>
          {loading ? 'Tracking...' : 'Track Order'}
        </button>
      </div>

      {result && (
        <div className={`alert ${result.error ? 'alert-danger' : 'alert-info'}`} style={{ marginTop: '2rem' }}>
          {result.response && (
            <div className="code-block">
              <strong>Response:</strong>
              <pre style={{ whiteSpace: 'pre-wrap' }}>{result.response}</pre>
            </div>
          )}
          {result.warning && (
            <div style={{ marginTop: '0.5rem' }}>
              <strong>Warning:</strong> {result.warning}
            </div>
          )}
          {result.error && (
            <>
              <strong>Error:</strong> {result.error}
            </>
          )}
        </div>
      )}
    </div>
  )
}

