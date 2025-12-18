import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'

// VULNERABLE: Weak authentication - predictable tokens
const users: Record<string, { username: string, role: string }> = {
  'admin': { username: 'admin', role: 'admin' },
  'john_doe': { username: 'john_doe', role: 'user' },
  'jane_smith': { username: 'jane_smith', role: 'user' },
  'mike_wilson': { username: 'mike_wilson', role: 'user' },
  'sarah_jones': { username: 'sarah_jones', role: 'user' },
  'david_brown': { username: 'david_brown', role: 'user' },
  'emily_davis': { username: 'emily_davis', role: 'user' },
  'chris_miller': { username: 'chris_miller', role: 'user' },
  'lisa_anderson': { username: 'lisa_anderson', role: 'user' },
  'robert_taylor': { username: 'robert_taylor', role: 'user' },
  'amanda_white': { username: 'amanda_white', role: 'user' },
  'james_martin': { username: 'james_martin', role: 'user' },
  'jennifer_thomas': { username: 'jennifer_thomas', role: 'user' },
  'william_jackson': { username: 'william_jackson', role: 'user' },
  'michelle_harris': { username: 'michelle_harris', role: 'user' },
  'richard_clark': { username: 'richard_clark', role: 'user' },
  'patricia_lewis': { username: 'patricia_lewis', role: 'user' },
  'daniel_robinson': { username: 'daniel_robinson', role: 'user' },
  'linda_walker': { username: 'linda_walker', role: 'user' },
  'mark_young': { username: 'mark_young', role: 'user' }
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { username, password, paymentMethod, shippingAddress } = body
  
  // VULNERABLE: Authentication bypass - weak password check
  const user = users[username]
  
  if (user && (password === 'password123' || password === username)) {
    // VULNERABLE: Weak session token
    const token = Buffer.from(`${username}:${password}`).toString('base64')
    
    const cookieStore = cookies()
    cookieStore.set('user_id', username)
    cookieStore.set('auth_token', token)
    
    return NextResponse.json({
      success: true,
      authenticated: true,
      token: token,
      user: user,
      order: {
        id: Math.floor(Math.random() * 1000000),
        status: 'processing',
        paymentMethod,
        shippingAddress
      },
      warning: 'VULNERABLE: Weak authentication - predictable tokens and weak passwords'
    })
  }
  
  return NextResponse.json({
    success: false,
    authenticated: false,
    message: 'Invalid credentials. Try: admin/admin123 or any username/password123'
  }, { status: 401 })
}

