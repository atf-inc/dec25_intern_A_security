'use client'

import { useState, useEffect, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'

function AdminLoginContent() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const router = useRouter()
  const searchParams = useSearchParams()

  useEffect(() => {
    // VULNERABILITY: Reflected XSS
    // Taking 'error' param from URL and displaying it dangerously
    const errorMsg = searchParams.get('error')
    if (errorMsg) {
      setError(errorMsg)
    }
  }, [searchParams])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      const data = await res.json()

      if (res.ok && data.success) {
        // Success
        alert(`Welcome, ${data.username}! Flag: DVWA{SQL_INJECTION_MASTER}`)
        router.push('/')
      } else {
        // Redirect with error to trigger XSS if payload provided
        // For standard errors, we just set state, but let's encourage URL manipulation
        setError(data.message || 'Login failed')
      }
    } catch (err) {
      setError('Connection error')
    }
  }

  return (
    <div className="max-w-md w-full p-8 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6 text-center text-red-600">Admin Login</h2>

      {/* VULNERABILITY: Renders HTML directly (XSS) */}
      {error && (
        <div
          className="mb-4 p-3 bg-red-100 text-red-700 rounded"
          dangerouslySetInnerHTML={{ __html: error }}
        />
      )}

      <form onSubmit={handleLogin} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500"
            placeholder="admin"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500"
          />
        </div>
        <button
          type="submit"
          className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
        >
          Sign In
        </button>
      </form>

      <div className="mt-4 text-xs text-gray-400 text-center">
        {/* Hint for attackers */}
        {/* <!-- Developers: Remember to fix the SQL query in /api/admin/login route. Using string concat is dangerous! --> */}
        <p>Protected by QuantumShield</p>
      </div>
    </div>
  )
}

export default function AdminLogin() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <Suspense fallback={<div>Loading Admin Panel...</div>}>
        <AdminLoginContent />
      </Suspense>
    </div>
  )
}
