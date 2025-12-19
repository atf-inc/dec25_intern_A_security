import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'
import sqlite3 from 'sqlite3'

// Initialize database
const db = new sqlite3.Database(':memory:')
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    balance REAL DEFAULT 0
  )`)
  
  // Create index for faster lookups
  db.run(`CREATE INDEX idx_username ON users(username)`)
  
  db.run(`INSERT INTO users (id, username, balance) VALUES 
    (1, 'admin', 10000.00),
    (2, 'john_doe', 1250.50),
    (3, 'jane_smith', 2850.75),
    (4, 'mike_wilson', 750.25),
    (5, 'sarah_jones', 1950.00),
    (6, 'david_brown', 3200.50),
    (7, 'emily_davis', 450.00),
    (8, 'chris_miller', 1650.75),
    (9, 'lisa_anderson', 2750.25),
    (10, 'robert_taylor', 850.50),
    (11, 'amanda_white', 2100.00),
    (12, 'james_martin', 1450.75),
    (13, 'jennifer_thomas', 3800.25),
    (14, 'william_jackson', 950.00),
    (15, 'michelle_harris', 2250.50),
    (16, 'richard_clark', 1750.75),
    (17, 'patricia_lewis', 3100.25),
    (18, 'daniel_robinson', 550.00),
    (19, 'linda_walker', 2650.50),
    (20, 'mark_young', 1350.75)`)
})

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { toUserId, amount } = body
  
  const cookieStore = cookies()
  const fromUserId = cookieStore.get('user_id')?.value || '1'
  
  // VULNERABLE: No CSRF protection
  // VULNERABLE: No authorization check - can transfer from any account
  // VULNERABLE: SQL Injection
  return new Promise((resolve) => {
    // VULNERABLE: Direct string concatenation
    const fromQuery = `SELECT * FROM users WHERE id = ${fromUserId}`
    const toQuery = `SELECT * FROM users WHERE id = ${toUserId}`
    
    db.get(fromQuery, (err: any, fromUser: any) => {
      if (err || !fromUser) {
        resolve(NextResponse.json({
          error: 'Source user not found',
          message: err?.message,
          warning: 'VULNERABLE: SQL Injection and IDOR!'
        }, { status: 400 }))
        return
      }
      
      db.get(toQuery, (err: any, toUser: any) => {
        if (err || !toUser) {
          resolve(NextResponse.json({
            error: 'Destination user not found',
            message: err?.message,
            warning: 'VULNERABLE: SQL Injection!'
          }, { status: 400 }))
          return
        }
        
        if (fromUser.balance < amount) {
          resolve(NextResponse.json({
            error: 'Insufficient balance',
            warning: 'VULNERABLE: No CSRF protection - can be exploited via malicious site!'
          }, { status: 400 }))
          return
        }
        
        // VULNERABLE: No transaction - race condition possible
        const updateFrom = `UPDATE users SET balance = balance - ${amount} WHERE id = ${fromUserId}`
        const updateTo = `UPDATE users SET balance = balance + ${amount} WHERE id = ${toUserId}`
        
        db.run(updateFrom, (err: any) => {
          if (err) {
            resolve(NextResponse.json({
              error: 'Transfer failed',
              message: err.message,
              warning: 'VULNERABLE: SQL Injection!'
            }, { status: 500 }))
            return
          }
          
          db.run(updateTo, (err: any) => {
            if (err) {
              resolve(NextResponse.json({
                error: 'Transfer failed',
                message: err.message,
                warning: 'VULNERABLE: SQL Injection!'
              }, { status: 500 }))
              return
            }
            
            resolve(NextResponse.json({
              success: true,
              message: `Transferred $${amount} from user ${fromUserId} to user ${toUserId}`,
              warning: 'VULNERABLE: No CSRF protection, SQL Injection, IDOR, and race conditions!'
            }))
          })
        })
      })
    })
  })
}
