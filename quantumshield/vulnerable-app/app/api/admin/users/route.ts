import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'
import sqlite3 from 'sqlite3'

// Initialize database
const db = new sqlite3.Database(':memory:')
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    email TEXT,
    password TEXT,
    role TEXT,
    balance REAL,
    created_at TEXT
  )`)
  
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

export async function GET(request: NextRequest) {
  const cookieStore = cookies()
  const role = cookieStore.get('role')?.value || 'user'
  const searchParams = request.nextUrl.searchParams
  const search = searchParams.get('search') || ''
  const sortBy = searchParams.get('sortBy') || 'id'
  const order = searchParams.get('order') || 'ASC'
  
  // VULNERABLE: Broken Access Control - role check can be bypassed
  // VULNERABLE: SQL Injection in search and sort parameters
  return new Promise((resolve) => {
    // VULNERABLE: Weak authorization check
    if (role !== 'admin') {
      resolve(NextResponse.json({
        error: 'Access denied',
        message: 'Admin access required',
        warning: 'VULNERABLE: Broken Access Control - role check can be bypassed by modifying cookie!'
      }, { status: 403 }))
      return
    }
    
    // VULNERABLE: Direct string concatenation
    let query = `SELECT id, username, email, role, balance, created_at FROM users WHERE 1=1`
    
    if (search) {
      query += ` AND (username LIKE '%${search}%' OR email LIKE '%${search}%')`
    }
    
    // VULNERABLE: SQL Injection in ORDER BY
    query += ` ORDER BY ${sortBy} ${order}`
    
    db.all(query, [], (err: any, rows: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query,
          warning: 'VULNERABLE: SQL Injection! Try: ?search=\' OR 1=1-- or ?sortBy=id; DROP TABLE users--'
        }, { status: 500 }))
      } else {
        resolve(NextResponse.json({
          users: rows,
          count: rows.length,
          query: query,
          warning: 'VULNERABLE: Broken Access Control and SQL Injection!'
        }))
      }
    })
  })
}

export async function DELETE(request: NextRequest) {
  const cookieStore = cookies()
  const role = cookieStore.get('role')?.value || 'user'
  const searchParams = request.nextUrl.searchParams
  const userId = searchParams.get('userId')
  
  // VULNERABLE: Broken Access Control
  // VULNERABLE: SQL Injection
  return new Promise((resolve) => {
    if (role !== 'admin') {
      resolve(NextResponse.json({
        error: 'Access denied',
        warning: 'VULNERABLE: Broken Access Control!'
      }, { status: 403 }))
      return
    }
    
    if (!userId) {
      resolve(NextResponse.json({
        error: 'User ID required'
      }, { status: 400 }))
      return
    }
    
    // VULNERABLE: Direct string concatenation
    const query = `DELETE FROM users WHERE id = ${userId}`
    
    db.run(query, (err: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query,
          warning: 'VULNERABLE: SQL Injection!'
        }, { status: 500 }))
      } else {
        resolve(NextResponse.json({
          success: true,
          message: `User ${userId} deleted`,
          query: query,
          warning: 'VULNERABLE: SQL Injection and Broken Access Control!'
        }))
      }
    })
  })
}
