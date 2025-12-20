'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'

export default function CartPage() {
  const [cart, setCart] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadCart()
  }, [])

  const loadCart = async () => {
    try {
      const response = await fetch('/api/cart')
      const data = await response.json()
      setCart(data.cart || [])
      setTotal(data.total || 0)
    } catch (error) {
      console.error('Error loading cart:', error)
    } finally {
      setLoading(false)
    }
  }

  const removeItem = async (productId: number) => {
    try {
      await fetch(`/api/cart?productId=${productId}`, { method: 'DELETE' })
      loadCart()
    } catch (error) {
      console.error('Error removing item:', error)
    }
  }

  const checkout = () => {
    // Redirect to checkout
    window.location.href = '/checkout'
  }

  if (loading) {
    return (
      <div className="container">
        <div className="alert alert-info">Loading cart...</div>
      </div>
    )
  }

  return (
    <div className="container">
      <h1>Shopping Cart</h1>
      
      <div className="alert alert-warning">
        <strong>⚠️ Vulnerability:</strong> Cart is vulnerable to IDOR attacks.
        Try changing the <code>user_id</code> cookie to access other users' carts.
      </div>

      {cart.length === 0 ? (
        <div className="alert alert-info">
          Your cart is empty. <Link href="/products">Browse products</Link>
        </div>
      ) : (
        <>
          {cart.map(item => (
            <div key={item.productId} className="cart-item">
              <div>
                <h3>{item.name}</h3>
                <p>${item.price.toFixed(2)} x {item.quantity}</p>
              </div>
              <div>
                <strong>${(item.price * item.quantity).toFixed(2)}</strong>
                <button 
                  onClick={() => removeItem(item.productId)}
                  className="btn btn-danger"
                  style={{ marginLeft: '1rem' }}
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
          
          <div className="cart-summary">
            <h2>Order Summary</h2>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
              <strong>Total:</strong>
              <strong style={{ fontSize: '1.5rem', color: '#667eea' }}>
                ${total.toFixed(2)}
              </strong>
            </div>
            <button onClick={checkout} className="btn btn-primary" style={{ width: '100%', fontSize: '1.2rem', padding: '1rem' }}>
              Proceed to Checkout
            </button>
          </div>
        </>
      )}
    </div>
  )
}

