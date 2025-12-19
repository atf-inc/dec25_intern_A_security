import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'
import sqlite3 from 'sqlite3'

// Initialize database
const db = new sqlite3.Database(':memory:')
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT,
    password TEXT,
    role TEXT DEFAULT 'user',
    balance REAL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`)
  
  // VULNERABLE: Plain text passwords (should be hashed)
  db.run(`INSERT INTO users (username, email, password, role, balance, created_at) VALUES 
    ('admin', 'admin@shopvuln.com', 'admin123', 'admin', 10000.00, '2024-01-01 10:00:00'),
    ('john_doe', 'john.doe@email.com', 'password123', 'user', 1250.50, '2024-01-02 11:15:00'),
    ('jane_smith', 'jane.smith@email.com', 'password123', 'user', 2850.75, '2024-01-03 09:30:00'),
    ('mike_wilson', 'mike.wilson@email.com', 'password123', 'user', 750.25, '2024-01-04 14:20:00'),
    ('sarah_jones', 'sarah.jones@email.com', 'password123', 'user', 1950.00, '2024-01-05 16:45:00'),
    ('david_brown', 'david.brown@email.com', 'password123', 'user', 3200.50, '2024-01-06 08:10:00'),
    ('emily_davis', 'emily.davis@email.com', 'password123', 'user', 450.00, '2024-01-07 12:30:00'),
    ('chris_miller', 'chris.miller@email.com', 'password123', 'user', 1650.75, '2024-01-08 15:20:00'),
    ('lisa_anderson', 'lisa.anderson@email.com', 'password123', 'user', 2750.25, '2024-01-09 10:50:00'),
    ('robert_taylor', 'robert.taylor@email.com', 'password123', 'user', 850.50, '2024-01-10 13:15:00'),
    ('amanda_white', 'amanda.white@email.com', 'password123', 'user', 2100.00, '2024-01-11 11:25:00'),
    ('james_martin', 'james.martin@email.com', 'password123', 'user', 1450.75, '2024-01-12 09:40:00'),
    ('jennifer_thomas', 'jennifer.thomas@email.com', 'password123', 'user', 3800.25, '2024-01-13 14:55:00'),
    ('william_jackson', 'william.jackson@email.com', 'password123', 'user', 950.00, '2024-01-14 16:10:00'),
    ('michelle_harris', 'michelle.harris@email.com', 'password123', 'user', 2250.50, '2024-01-15 08:30:00'),
    ('richard_clark', 'richard.clark@email.com', 'password123', 'user', 1750.75, '2024-01-16 12:45:00'),
    ('patricia_lewis', 'patricia.lewis@email.com', 'password123', 'user', 3100.25, '2024-01-17 15:20:00'),
    ('daniel_robinson', 'daniel.robinson@email.com', 'password123', 'user', 550.00, '2024-01-18 10:15:00'),
    ('linda_walker', 'linda.walker@email.com', 'password123', 'user', 2650.50, '2024-01-19 13:50:00'),
    ('mark_young', 'mark.young@email.com', 'password123', 'user', 1350.75, '2024-01-20 11:35:00')`)
})

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { username, password } = body
  
  // VULNERABLE: SQL Injection in login
  // VULNERABLE: No rate limiting
  // VULNERABLE: Weak password storage (plain text)
  // VULNERABLE: Predictable session tokens
  return new Promise((resolve) => {
    // VULNERABLE: Direct string concatenation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`
    
    db.get(query, (err: any, user: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query,
          warning: 'VULNERABLE: SQL Injection in login! Try: username=admin\' OR \'1\'=\'1'
        }, { status: 500 }))
      } else if (user) {
        // VULNERABLE: Weak session token (base64 encoded username:password)
        const token = Buffer.from(`${user.username}:${user.password}`).toString('base64')
        
        const cookieStore = cookies()
        cookieStore.set('user_id', user.id.toString())
        cookieStore.set('username', user.username)
        cookieStore.set('auth_token', token)
        cookieStore.set('role', user.role)
        
        resolve(NextResponse.json({
          success: true,
          authenticated: true,
          token: token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
          },
          warning: 'VULNERABLE: SQL Injection, weak authentication, predictable tokens!'
        }))
      } else {
        resolve(NextResponse.json({
          success: false,
          authenticated: false,
          message: 'Invalid credentials',
          query: query
        }, { status: 401 }))
      }
    })
  })
}

export async function GET(request: NextRequest) {
  // VULNERABLE: Information disclosure - shows all users
  return new Promise((resolve) => {
    const query = `SELECT id, username, email, role FROM users`
    
    db.all(query, [], (err: any, rows: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message
        }, { status: 500 }))
      } else {
        resolve(NextResponse.json({
          users: rows,
          warning: 'VULNERABLE: Information disclosure - user list exposed!'
        }))
      }
    })
  })
}
