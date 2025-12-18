import { NextRequest, NextResponse } from 'next/server'
import { getDatabase } from '../../../../lib/database'

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const userId = searchParams.get('id') || ''
  const db = getDatabase()
  
  // VULNERABLE: Direct SQL injection - no parameterization
  // Handle both numeric ID and username
  return new Promise((resolve) => {
    let query: string
    
    // Check if input is numeric (ID) or string (username)
    if (userId && !isNaN(Number(userId)) && userId.trim() !== '') {
      // Numeric ID
      query = `SELECT * FROM users WHERE id = ${userId}`
    } else if (userId) {
      // Username or email search
      query = `SELECT * FROM users WHERE username = '${userId}' OR email = '${userId}'`
    } else {
      query = `SELECT * FROM users WHERE 1=1`
    }
    
    db.all(query, (err: any, rows: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query
        }, { status: 500 }))
      } else {
        // Handle user not found case
        if (rows.length === 0 && userId) {
          resolve(NextResponse.json({
            success: false,
            error: 'User not found',
            query: query,
            message: `No user found with ID/username/email: ${userId}`,
            results: []
          }, { status: 404 }))
        } else {
          resolve(NextResponse.json({
            success: true,
            query: query,
            results: rows,
            count: rows.length,
            message: rows.length > 0 
              ? 'VULNERABLE: SQL injection possible. Try: ?id=1 OR 1=1 or ?id=john_doe'
              : 'No results found'
          }))
        }
      }
    })
  })
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { username, password } = body
  const db = getDatabase()
  
  // VULNERABLE: SQL injection in login
  return new Promise((resolve) => {
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`
    
    db.all(query, (err: any, rows: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query
        }, { status: 500 }))
      } else {
        if (rows.length > 0) {
          resolve(NextResponse.json({
            success: true,
            authenticated: true,
            user: rows[0],
            query: query
          }))
        } else {
          resolve(NextResponse.json({
            success: false,
            authenticated: false,
            error: 'Invalid credentials',
            query: query,
            message: 'User not found or incorrect password'
          }, { status: 401 }))
        }
      }
    })
  })
}

