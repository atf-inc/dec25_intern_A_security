'use client'

import { useState } from 'react'
import Link from 'next/link'

export default function AdminPage() {
  const [file, setFile] = useState<File | null>(null)
  const [action, setAction] = useState('upload')
  const [fileToRead, setFileToRead] = useState('test.txt')
  const [result, setResult] = useState<any>(null)
  const [fileContent, setFileContent] = useState<any>(null)
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
      formData.append('action', action)

      const response = await fetch('/api/admin/upload', {
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

  const readFile = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/admin/files?file=${encodeURIComponent(fileToRead)}`)
      const data = await response.json()
      setFileContent(data)
    } catch (error: any) {
      setFileContent({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container">
      <h1>Admin Panel</h1>
      
      <div className="alert alert-danger">
        <strong>⚠️ Multiple Vulnerabilities:</strong>
        <ul style={{ marginTop: '0.5rem', marginLeft: '1.5rem' }}>
          <li><strong>File Upload:</strong> No validation - can upload malicious files</li>
          <li><strong>Command Injection:</strong> File processing executes system commands</li>
          <li><strong>Path Traversal:</strong> Can read any file on the system</li>
        </ul>
      </div>

      <div className="admin-panel">
        <div style={{ marginBottom: '2rem', padding: '1rem', background: '#f5f5f5', borderRadius: '5px' }}>
          <Link href="/admin/import" className="btn btn-secondary">
            Product Import (XXE & Deserialization) →
          </Link>
        </div>
        
        <div className="admin-section">
          <h2>1. Upload Product Image</h2>
          <div className="alert alert-warning">
            <strong>Vulnerable:</strong> No file type validation, no size limit, no content scanning
          </div>
          
          <div className="form-group">
            <label>Select File:</label>
            <input type="file" onChange={handleFileChange} />
            {file && (
              <div style={{ marginTop: '0.5rem', color: '#666' }}>
                Selected: {file.name} ({(file.size / 1024).toFixed(2)} KB)
              </div>
            )}
          </div>
          
          <div className="form-group">
            <label>Action:</label>
            <select value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="upload">Just Upload</option>
              <option value="process">Upload & Process (Command Injection)</option>
            </select>
          </div>
          
          <button onClick={uploadFile} className="btn btn-primary" disabled={loading || !file}>
            {loading ? 'Uploading...' : 'Upload File'}
          </button>
        </div>

        <div className="admin-section">
          <h2>2. Read System Files</h2>
          <div className="alert alert-warning">
            <strong>Vulnerable:</strong> Path traversal allows reading any file
          </div>
          
          <div className="form-group">
            <label>File Path (Vulnerable to Path Traversal):</label>
            <input
              type="text"
              value={fileToRead}
              onChange={(e) => setFileToRead(e.target.value)}
              placeholder="../../../package.json"
            />
          </div>
          
          <button onClick={readFile} className="btn btn-primary" disabled={loading}>
            {loading ? 'Reading...' : 'Read File'}
          </button>
        </div>
      </div>

      {result && (
        <div className={`alert ${result.error ? 'alert-danger' : 'alert-success'}`} style={{ marginTop: '2rem' }}>
          <h3>Upload Result:</h3>
          {result.command && (
            <div className="code-block">
              <strong>Command Executed:</strong> {result.command}
            </div>
          )}
          {result.fileInfo && (
            <div className="code-block">
              <strong>File Info:</strong>
              <pre>{result.fileInfo}</pre>
            </div>
          )}
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}

      {fileContent && (
        <div className={`alert ${fileContent.error ? 'alert-danger' : 'alert-info'}`} style={{ marginTop: '2rem' }}>
          <h3>File Content:</h3>
          {fileContent.content && (
            <div className="code-block">
              <pre style={{ whiteSpace: 'pre-wrap' }}>{fileContent.content}</pre>
            </div>
          )}
          {fileContent.warning && (
            <div style={{ marginTop: '0.5rem' }}>
              <strong>Warning:</strong> {fileContent.warning}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

