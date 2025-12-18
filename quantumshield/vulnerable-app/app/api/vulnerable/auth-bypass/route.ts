import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'

// In-memory "database" - very insecure
const users: Record<string, { username: string, password: string, role: string }> = {
  'admin': { username: 'admin', password: 'admin123', role: 'admin' },
  'john_doe': { username: 'john_doe', password: 'password123', role: 'user' },
  'jane_smith': { username: 'jane_smith', password: 'password123', role: 'user' },
  'mike_wilson': { username: 'mike_wilson', password: 'password123', role: 'user' },
  'sarah_jones': { username: 'sarah_jones', password: 'password123', role: 'user' },
  'david_brown': { username: 'david_brown', password: 'password123', role: 'user' },
  'emily_davis': { username: 'emily_davis', password: 'password123', role: 'user' },
  'chris_miller': { username: 'chris_miller', password: 'password123', role: 'user' },
  'lisa_anderson': { username: 'lisa_anderson', password: 'password123', role: 'user' },
  'robert_taylor': { username: 'robert_taylor', password: 'password123', role: 'user' },
  'amanda_white': { username: 'amanda_white', password: 'password123', role: 'user' },
  'james_martin': { username: 'james_martin', password: 'password123', role: 'user' },
  'jennifer_thomas': { username: 'jennifer_thomas', password: 'password123', role: 'user' },
  'william_jackson': { username: 'william_jackson', password: 'password123', role: 'user' },
  'michelle_harris': { username: 'michelle_harris', password: 'password123', role: 'user' },
  'richard_clark': { username: 'richard_clark', password: 'password123', role: 'user' },
  'patricia_lewis': { username: 'patricia_lewis', password: 'password123', role: 'user' },
  'daniel_robinson': { username: 'daniel_robinson', password: 'password123', role: 'user' },
  'linda_walker': { username: 'linda_walker', password: 'password123', role: 'user' },
  'mark_young': { username: 'mark_young', password: 'password123', role: 'user' }
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { username, password } = body
  
  // VULNERABLE: Weak authentication
  const user = users[username]
  
  if (user && user.password === password) {
    // VULNERABLE: Weak session token (predictable)
    const token = Buffer.from(`${username}:${password}`).toString('base64')
    
    return NextResponse.json({
      success: true,
      authenticated: true,
      token: token,
      user: { username: user.username, role: user.role },
      warning: 'VULNERABLE: Weak authentication and predictable tokens'
    })
  }
  
  return NextResponse.json({
    success: false,
    authenticated: false,
    message: 'Invalid credentials'
  }, { status: 401 })
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const token = searchParams.get('token') || ''
  
  // VULNERABLE: Token validation is weak
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf-8')
    const [username, password] = decoded.split(':')
    
    if (users[username] && users[username].password === password) {
      return NextResponse.json({
        success: true,
        authenticated: true,
        user: { username, role: users[username].role },
        warning: 'VULNERABLE: Token can be easily decoded and manipulated'
      })
    }
  } catch (e) {
    // Ignore errors
  }
  
  return NextResponse.json({
    success: false,
    authenticated: false,
    message: 'Invalid token'
  }, { status: 401 })
}

