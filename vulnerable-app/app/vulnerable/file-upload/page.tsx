'use client'

import { useState } from 'react'

export default function FileUploadPage() {
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
    }
  }

  const uploadFile = async () => {
    if (!file) {
      setResult({ error: 'Please select a file' })
      return
    }

    setLoading(true)
    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch('/api/vulnerable/file-upload', {
        method: 'POST',
        body: formData
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
      <h1>File Upload Vulnerability</h1>
      
      <div className="warning" style={{ marginBottom: '20px' }}>
        <strong>⚠️ WARNING:</strong> This endpoint accepts any file type without validation!
      </div>

      <div className="info-box">
        <strong>Test Malicious File Upload:</strong>
        <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
          <li>PHP Web Shell: <code>&lt;?php system($_GET['cmd']); ?&gt;</code></li>
          <li>JSP Web Shell: <code>&lt;% Runtime.getRuntime().exec(request.getParameter("cmd")); %&gt;</code></li>
          <li>Executable files: <code>.exe, .sh, .bat</code></li>
        </ul>
      </div>

      <div className="form-group">
        <label>Select file to upload (No validation):</label>
        <input
          type="file"
          onChange={handleFileChange}
        />
        {file && (
          <div style={{ marginTop: '10px', color: '#666' }}>
            Selected: {file.name} ({(file.size / 1024).toFixed(2)} KB)
          </div>
        )}
      </div>

      <button onClick={uploadFile} disabled={loading || !file}>
        {loading ? 'Uploading...' : 'Upload File'}
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

