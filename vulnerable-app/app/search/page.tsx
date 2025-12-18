'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'

export default function SearchPage() {
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [minPrice, setMinPrice] = useState('')
  const [maxPrice, setMaxPrice] = useState('')
  const [products, setProducts] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)

  const searchProducts = async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      if (search) params.append('search', search)
      if (category) params.append('category', category)
      if (minPrice) params.append('minPrice', minPrice)
      if (maxPrice) params.append('maxPrice', maxPrice)
      
      const response = await fetch(`/api/products?${params.toString()}`)
      const data = await response.json()
      
      if (data.error) {
        setResult({ error: data.message, query: data.query })
      } else {
        setProducts(data.products || [])
        setResult({ query: data.query, warning: data.warning })
      }
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  // VULNERABLE: DOM-based XSS in URL parameters
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const urlSearch = urlParams.get('q')
    if (urlSearch) {
      setSearch(urlSearch)
      // VULNERABLE: Direct rendering of URL parameter
      document.getElementById('search-results')?.insertAdjacentHTML('beforeend', 
        `<div class="alert alert-info">Searching for: ${urlSearch}</div>`
      )
    }
  }, [])

  return (
    <div className="container">
      <h1>Search Products</h1>
      
      <div className="alert alert-warning">
        <strong>⚠️ Vulnerability:</strong> This search feature is vulnerable to SQL Injection and XSS attacks.
        <ul style={{ marginTop: '0.5rem', marginLeft: '1.5rem' }}>
          <li>SQL Injection: Try <code>test' OR '1'='1</code> in search</li>
          <li>XSS: Try <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> in search</li>
          <li>DOM XSS: Add <code>?q=&lt;img src=x onerror=alert('XSS')&gt;</code> to URL</li>
        </ul>
      </div>

      <div className="search-container">
        <div className="form-group">
          <label>Search Products (Vulnerable to SQL Injection & XSS):</label>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search products..."
            className="search-input"
            onKeyPress={(e) => e.key === 'Enter' && searchProducts()}
          />
        </div>

        <div className="form-group">
          <label>Category:</label>
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">All Categories</option>
            <option value="Electronics">Electronics</option>
            <option value="Audio">Audio</option>
            <option value="Wearables">Wearables</option>
            <option value="Gaming">Gaming</option>
          </select>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div className="form-group">
            <label>Min Price:</label>
            <input
              type="number"
              value={minPrice}
              onChange={(e) => setMinPrice(e.target.value)}
              placeholder="0"
            />
          </div>
          <div className="form-group">
            <label>Max Price:</label>
            <input
              type="number"
              value={maxPrice}
              onChange={(e) => setMaxPrice(e.target.value)}
              placeholder="2000"
            />
          </div>
        </div>

        <button onClick={searchProducts} className="btn btn-primary" disabled={loading}>
          {loading ? 'Searching...' : 'Search Products'}
        </button>
      </div>

      <div id="search-results"></div>

      {result && (
        <div className={`alert ${result.error ? 'alert-danger' : 'alert-info'}`}>
          {result.error && (
            <>
              <strong>Error:</strong> {result.error}
              {result.query && (
                <div className="code-block" style={{ marginTop: '0.5rem' }}>
                  Query: {result.query}
                </div>
              )}
            </>
          )}
          {result.warning && <><strong>Warning:</strong> {result.warning}</>}
          {result.query && !result.error && (
            <div className="code-block" style={{ marginTop: '0.5rem' }}>
              SQL Query: {result.query}
            </div>
          )}
        </div>
      )}

      {products.length > 0 && (
        <>
          <h2 style={{ marginTop: '2rem', marginBottom: '1rem' }}>
            Search Results ({products.length} products)
          </h2>
          <div className="products-grid">
            {products.map(product => (
              <Link key={product.id} href={`/products/${product.id}`} style={{ textDecoration: 'none' }}>
                <div className="product-card">
                  <div className="product-image" style={{ 
                    fontSize: '5rem', 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'center' 
                  }}>
                    {product.image || '📦'}
                  </div>
                  <div className="product-title">{product.name}</div>
                  <div className="product-price">${product.price.toFixed(2)}</div>
                  <div className="product-description">{product.description}</div>
                  <button className="btn btn-primary" style={{ width: '100%' }}>
                    View Details
                  </button>
                </div>
              </Link>
            ))}
          </div>
        </>
      )}

      {products.length === 0 && !loading && result && !result.error && (
        <div className="alert alert-info">
          No products found. Try a different search term.
        </div>
      )}
    </div>
  )
}

