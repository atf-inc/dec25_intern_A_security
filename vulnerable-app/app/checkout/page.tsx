'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'

export default function CheckoutPage() {
  const router = useRouter()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [paymentMethod, setPaymentMethod] = useState('credit_card')
  const [shippingAddress, setShippingAddress] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handleCheckout = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          paymentMethod,
          shippingAddress
        })
      })
      const data = await response.json()
      setResult(data)
      if (data.success) {
        setTimeout(() => {
          router.push('/orders')
        }, 2000)
      }
    } catch (error: any) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container">
      <h1>Checkout</h1>
      
      <div className="alert alert-warning">
        <strong>⚠️ Vulnerability:</strong> Authentication is weak and vulnerable to bypass.
        <ul style={{ marginTop: '0.5rem', marginLeft: '1.5rem' }}>
          <li>Try: <code>admin/password123</code> or <code>user1/password123</code></li>
          <li>SQL Injection: <code>admin' OR '1'='1</code></li>
          <li>Weak passwords are accepted</li>
        </ul>
      </div>

      <div style={{ background: 'white', padding: '2rem', borderRadius: '10px', boxShadow: '0 2px 10px rgba(0,0,0,0.1)' }}>
        <h2>Login / Create Account</h2>
        <div className="form-group">
          <label>Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="admin"
          />
        </div>
        <div className="form-group">
          <label>Password (Vulnerable):</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="password123"
          />
        </div>

        <h2 style={{ marginTop: '2rem' }}>Shipping Information</h2>
        <div className="form-group">
          <label>Shipping Address:</label>
          <textarea
            value={shippingAddress}
            onChange={(e) => setShippingAddress(e.target.value)}
            placeholder="123 Main St, City, State, ZIP"
            rows={3}
          />
        </div>

        <h2 style={{ marginTop: '2rem' }}>Payment Method</h2>
        <div className="form-group">
          <select value={paymentMethod} onChange={(e) => setPaymentMethod(e.target.value)}>
            <option value="credit_card">Credit Card</option>
            <option value="paypal">PayPal</option>
            <option value="bank_transfer">Bank Transfer</option>
          </select>
        </div>

        <button 
          onClick={handleCheckout} 
          className="btn btn-primary"
          disabled={loading}
          style={{ width: '100%', fontSize: '1.2rem', padding: '1rem', marginTop: '1rem' }}
        >
          {loading ? 'Processing...' : 'Complete Order'}
        </button>
      </div>

      {result && (
        <div className={`alert ${result.error ? 'alert-danger' : result.success ? 'alert-success' : 'alert-info'}`} style={{ marginTop: '2rem' }}>
          {result.success && (
            <>
              <strong>Order Placed Successfully!</strong>
              <p>Order ID: {result.order?.id}</p>
              <p>Redirecting to orders...</p>
            </>
          )}
          {result.error && (
            <>
              <strong>Error:</strong> {result.error}
            </>
          )}
          {result.warning && (
            <div style={{ marginTop: '0.5rem', fontSize: '0.9rem' }}>
              <strong>Warning:</strong> {result.warning}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

