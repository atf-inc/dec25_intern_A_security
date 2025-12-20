import Link from 'next/link'

export default function Home() {
  return (
    <div className="container">
      <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
        <h1 style={{ fontSize: '3rem', color: '#333', marginBottom: '1rem' }}>
          Welcome to ShopVuln
        </h1>
        <p style={{ fontSize: '1.2rem', color: '#666' }}>
          Your one-stop shop for all your needs
        </p>
      </div>

      <div className="alert alert-warning">
        <strong>⚠️ Security Notice:</strong> This e-commerce platform contains intentional vulnerabilities for WAF testing. 
        All features are functional but vulnerable to various attacks. Use only in isolated testing environments.
      </div>

      <div style={{ marginTop: '3rem' }}>
        <h2 style={{ marginBottom: '1.5rem', color: '#333' }}>Featured Products</h2>
        <div className="products-grid">
          {[
            { id: 1, name: 'Laptop Pro', price: 1299.99, image: '💻' },
            { id: 2, name: 'Smartphone X', price: 899.99, image: '📱' },
            { id: 3, name: 'Wireless Headphones', price: 199.99, image: '🎧' },
            { id: 4, name: 'Smart Watch', price: 349.99, image: '⌚' },
            { id: 5, name: 'Tablet Air', price: 599.99, image: '📱' },
            { id: 6, name: 'Gaming Mouse', price: 79.99, image: '🖱️' },
          ].map(product => (
            <Link key={product.id} href={`/products/${product.id}`} style={{ textDecoration: 'none' }}>
              <div className="product-card">
                <div className="product-image" style={{ 
                  fontSize: '5rem', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center' 
                }}>
                  {product.image}
                </div>
                <div className="product-title">{product.name}</div>
                <div className="product-price">${product.price.toFixed(2)}</div>
                <button className="btn btn-primary" style={{ width: '100%' }}>
                  View Details
                </button>
              </div>
            </Link>
          ))}
        </div>
      </div>

      <div style={{ marginTop: '4rem', background: 'white', padding: '2rem', borderRadius: '10px', boxShadow: '0 2px 10px rgba(0,0,0,0.1)' }}>
        <h2 style={{ marginBottom: '1rem', color: '#333' }}>Quick Links</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
          <Link href="/products" className="btn btn-secondary">Browse All Products</Link>
          <Link href="/search" className="btn btn-secondary">Search Products</Link>
          <Link href="/cart" className="btn btn-secondary">Shopping Cart</Link>
          <Link href="/profile" className="btn btn-secondary">My Account</Link>
        </div>
      </div>
    </div>
  )
}
