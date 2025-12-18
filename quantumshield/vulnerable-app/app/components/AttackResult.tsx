'use client'

interface AttackResultProps {
  result: any
}

export default function AttackResult({ result }: AttackResultProps) {
  if (!result) return null

  if (result.blocked) {
    return (
      <div style={{ 
        padding: '1.5rem', 
        background: 'linear-gradient(135deg, #fee 0%, #fdd 100%)', 
        border: '3px solid #f00', 
        borderRadius: '12px',
        fontSize: '1.2rem',
        textAlign: 'center',
        color: '#c00',
        boxShadow: '0 4px 6px rgba(255, 0, 0, 0.1)',
        marginTop: '1rem'
      }}>
        <div style={{ fontSize: '3rem', marginBottom: '0.5rem' }}>🚫</div>
        <strong style={{ fontSize: '1.3rem' }}>
          {result.message || 'Request blocked by firewall'}
        </strong>
      </div>
    )
  }

  if (result.error) {
    return (
      <div style={{ 
        padding: '1rem', 
        background: '#fee', 
        border: '1px solid #f00', 
        borderRadius: '8px',
        color: '#c00',
        marginTop: '1rem'
      }}>
        <strong>Error:</strong> {result.error}
      </div>
    )
  }

  return (
    <div className="result success" style={{ marginTop: '1rem' }}>
      <h3>Result:</h3>
      <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', background: '#f5f5f5', padding: '1rem', borderRadius: '8px' }}>
        {JSON.stringify(result, null, 2)}
      </pre>
    </div>
  )
}
