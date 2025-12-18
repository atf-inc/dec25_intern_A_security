import Link from 'next/link'

export default function VulnerabilitiesPage() {
  const vulnerabilities = [
    {
      name: 'SQL Injection',
      location: 'Search & Product Filters',
      path: '/vulnerable/sql-injection',
      description: 'SQL queries constructed directly from user input',
      attacks: ['test\' OR \'1\'=\'1', '1 UNION SELECT null, null, null']
    },
    {
      name: 'XSS (Cross-Site Scripting)',
      location: 'Search, Reviews, Product Pages',
      path: '/vulnerable/xss',
      description: 'Reflected, stored, and DOM-based XSS vulnerabilities',
      attacks: ['<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>']
    },
    {
      name: 'Command Injection',
      location: 'Admin Panel - File Processing',
      path: '/vulnerable/command-injection',
      description: 'OS commands executed from user input',
      attacks: ['localhost; ls', 'localhost && dir']
    },
    {
      name: 'Path Traversal',
      location: 'Admin Panel - File Reading',
      path: '/vulnerable/path-traversal',
      description: 'Unrestricted file system access',
      attacks: ['../../../package.json', '../../../etc/passwd']
    },
    {
      name: 'File Upload',
      location: 'Admin Panel',
      path: '/vulnerable/file-upload',
      description: 'No file type or content validation',
      attacks: ['PHP web shell', 'Executable files']
    },
    {
      name: 'Authentication Bypass',
      location: 'Checkout',
      path: '/vulnerable/auth-bypass',
      description: 'Weak authentication and predictable tokens',
      attacks: ['admin/password123', 'admin\' OR \'1\'=\'1']
    },
    {
      name: 'IDOR (Insecure Direct Object Reference)',
      location: 'User Profile, Shopping Cart',
      path: '/vulnerable/idor',
      description: 'No authorization checks on user data',
      attacks: ['Change user ID in URL', 'Modify other users\' data']
    },
    {
      name: 'SSRF (Server-Side Request Forgery)',
      location: 'Order Tracking',
      path: '/vulnerable/ssrf',
      description: 'Unrestricted server-side requests',
      attacks: ['http://localhost:22', 'file:///etc/passwd']
    },
    {
      name: 'XXE (XML External Entity)',
      location: 'Admin - Product Import',
      path: '/vulnerable/xxe',
      description: 'External entity processing enabled',
      attacks: ['<!ENTITY xxe SYSTEM "file:///etc/passwd">']
    },
    {
      name: 'Insecure Deserialization',
      location: 'Admin - Product Import',
      path: '/vulnerable/deserialization',
      description: 'Using eval() for deserialization',
      attacks: ['{"__proto__": {"isAdmin": true}}']
    },
  ]

  return (
    <div className="container">
      <h1>Vulnerability Reference</h1>
      
      <div className="alert alert-info">
        This page lists all vulnerabilities in the e-commerce application.
        Each vulnerability is integrated into real e-commerce features.
      </div>

      <div style={{ display: 'grid', gap: '1.5rem', marginTop: '2rem' }}>
        {vulnerabilities.map((vuln, index) => (
          <div key={index} style={{
            background: 'white',
            padding: '1.5rem',
            borderRadius: '10px',
            boxShadow: '0 2px 10px rgba(0,0,0,0.1)',
            borderLeft: '4px solid #667eea'
          }}>
            <h2 style={{ color: '#667eea', marginBottom: '0.5rem' }}>{vuln.name}</h2>
            <p style={{ color: '#666', marginBottom: '0.5rem' }}><strong>Location:</strong> {vuln.location}</p>
            <p style={{ color: '#333', marginBottom: '1rem' }}>{vuln.description}</p>
            <div style={{ marginBottom: '1rem' }}>
              <strong>Test Attacks:</strong>
              <ul style={{ marginLeft: '1.5rem', marginTop: '0.5rem' }}>
                {vuln.attacks.map((attack, i) => (
                  <li key={i} style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>{attack}</li>
                ))}
              </ul>
            </div>
            <Link href={vuln.path} className="btn btn-primary">
              Test Vulnerability →
            </Link>
          </div>
        ))}
      </div>
    </div>
  )
}

