import './globals.css'
import Link from 'next/link'

export const metadata = {
  title: 'ShopVuln - E-Commerce Platform',
  description: 'Vulnerable e-commerce platform for WAF testing',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>
        <header className="header">
          <div className="header-content">
            <Link href="/" className="logo">
              🛒 ShopVuln
            </Link>
            <nav>
              <ul className="nav-links">
                <li><Link href="/">Home</Link></li>
                <li><Link href="/products">Products</Link></li>
                <li><Link href="/cart">Cart</Link></li>
                <li><Link href="/profile">Profile</Link></li>
                <li><Link href="/admin">Admin</Link></li>
                <li><Link href="/vulnerabilities">Vulnerabilities</Link></li>
              </ul>
            </nav>
          </div>
        </header>
        <main>
          {children}
        </main>
        <footer style={{
          background: '#333',
          color: 'white',
          padding: '2rem',
          textAlign: 'center',
          marginTop: '4rem'
        }}>
          <p>⚠️ This is a vulnerable application for WAF testing only. Do not use in production.</p>
          <p style={{ marginTop: '0.5rem', fontSize: '0.9rem', opacity: 0.8 }}>
            WAF Status: {process.env.WAF_ENABLED === 'true' ? 
              <span style={{ color: '#4caf50' }}>ENABLED ✓</span> : 
              <span style={{ color: '#f44336' }}>DISABLED ✗</span>}
          </p>
        </footer>
      </body>
    </html>
  )
}
