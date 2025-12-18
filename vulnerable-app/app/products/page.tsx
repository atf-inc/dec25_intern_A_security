'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'

export default function ProductsPage() {
  const [products, setProducts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadProducts()
  }, [])

  const loadProducts = async () => {
    try {
      const response = await fetch('/api/products')
      const data = await response.json()
      setProducts(data.products || [])
    } catch (error) {
      console.error('Error loading products:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="container">
        <div className="alert alert-info">Loading products...</div>
      </div>
    )
  }

  return (
    <div className="container">
      <h1>All Products</h1>
      
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
    </div>
  )
}

