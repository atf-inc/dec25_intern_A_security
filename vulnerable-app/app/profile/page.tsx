'use client'

import { useState, useEffect } from 'react'

export default function ProfilePage() {
  const [userId, setUserId] = useState('1')
  const [user, setUser] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [editing, setEditing] = useState(false)
  const [formData, setFormData] = useState<any>({})

  const loadUser = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/users/${userId}`)
      const data = await response.json()
      setUser(data.user)
      setFormData(data.user || {})
    } catch (error) {
      console.error('Error loading user:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadUser()
  }, [userId])

  const saveProfile = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })
      const data = await response.json()
      setUser(data.user)
      setEditing(false)
    } catch (error) {
      console.error('Error saving profile:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container">
      <h1>User Profile</h1>
      
      <div className="alert alert-warning">
        <strong>⚠️ Vulnerability:</strong> This profile page is vulnerable to IDOR attacks.
        <ul style={{ marginTop: '0.5rem', marginLeft: '1.5rem' }}>
          <li>Change user ID to access other users' profiles</li>
          <li>Try: 1, 2, 3 in the URL or input field</li>
          <li>Can modify any user's data without authorization</li>
        </ul>
      </div>

      <div className="form-group">
        <label>User ID (Vulnerable to IDOR):</label>
        <input
          type="number"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="1"
        />
        <button onClick={loadUser} className="btn btn-secondary" style={{ marginTop: '0.5rem' }}>
          Load Profile
        </button>
      </div>

      {loading && !user && (
        <div className="alert alert-info">Loading profile...</div>
      )}

      {user && (
        <div style={{ background: 'white', padding: '2rem', borderRadius: '10px', boxShadow: '0 2px 10px rgba(0,0,0,0.1)' }}>
          {!editing ? (
            <>
              <h2>{user.username}'s Profile</h2>
              <div style={{ marginTop: '1rem' }}>
                <p><strong>Email:</strong> {user.email}</p>
                <p><strong>Balance:</strong> ${user.balance.toFixed(2)}</p>
                <p><strong>Address:</strong> {user.address}</p>
                <p><strong>Phone:</strong> {user.phone}</p>
              </div>
              <button onClick={() => setEditing(true)} className="btn btn-primary" style={{ marginTop: '1rem' }}>
                Edit Profile
              </button>
            </>
          ) : (
            <>
              <h2>Edit Profile</h2>
              <div className="form-group">
                <label>Email:</label>
                <input
                  type="email"
                  value={formData.email || ''}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label>Balance:</label>
                <input
                  type="number"
                  value={formData.balance || 0}
                  onChange={(e) => setFormData({ ...formData, balance: parseFloat(e.target.value) })}
                />
              </div>
              <div className="form-group">
                <label>Address:</label>
                <textarea
                  value={formData.address || ''}
                  onChange={(e) => setFormData({ ...formData, address: e.target.value })}
                  rows={3}
                />
              </div>
              <div className="form-group">
                <label>Phone:</label>
                <input
                  type="text"
                  value={formData.phone || ''}
                  onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                />
              </div>
              <div style={{ display: 'flex', gap: '1rem' }}>
                <button onClick={saveProfile} className="btn btn-primary" disabled={loading}>
                  {loading ? 'Saving...' : 'Save Changes'}
                </button>
                <button onClick={() => { setEditing(false); setFormData(user); }} className="btn btn-secondary">
                  Cancel
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

