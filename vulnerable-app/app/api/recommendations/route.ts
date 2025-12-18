import { NextRequest, NextResponse } from 'next/server'
import sqlite3 from 'sqlite3'

// Initialize database
const db = new sqlite3.Database(':memory:')
db.serialize(() => {
  db.run(`CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    description TEXT,
    price REAL,
    category TEXT,
    image TEXT,
    stock INTEGER,
    views INTEGER DEFAULT 0,
    purchases INTEGER DEFAULT 0
  )`)
  
  db.run(`INSERT INTO products (name, description, price, category, image, stock, views, purchases) VALUES 
    ('Laptop Pro', 'High-performance laptop', 1299.99, 'Electronics', '💻', 50, 1200, 45),
    ('Smartphone X', 'Latest smartphone', 899.99, 'Electronics', '📱', 100, 2500, 180),
    ('Wireless Headphones', 'Premium headphones', 199.99, 'Audio', '🎧', 75, 800, 60),
    ('Smart Watch', 'Fitness tracking watch', 349.99, 'Wearables', '⌚', 60, 600, 40),
    ('Tablet Air', 'Lightweight tablet', 599.99, 'Electronics', '📱', 40, 400, 25),
    ('Gaming Mouse', 'Precision mouse', 79.99, 'Gaming', '🖱️', 200, 1500, 120)`)
})

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const userId = searchParams.get('userId') || '1'
  const category = searchParams.get('category') || ''
  const limit = searchParams.get('limit') || '5'
  
  // VULNERABLE: SQL Injection in multiple parameters
  return new Promise((resolve) => {
    let query = `SELECT * FROM products WHERE 1=1`
    
    // VULNERABLE: Direct string concatenation
    if (category) {
      query += ` AND category = '${category}'`
    }
    
    // VULNERABLE: No input validation on limit
    query += ` ORDER BY purchases DESC, views DESC LIMIT ${limit}`
    
    db.all(query, [], (err: any, rows: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query,
          warning: 'VULNERABLE: SQL Injection in recommendations! Try: ?category=\' OR 1=1--'
        }, { status: 500 }))
      } else {
        resolve(NextResponse.json({
          recommendations: rows,
          userId: userId,
          query: query,
          warning: 'VULNERABLE: SQL Injection and IDOR - can access recommendations for any user!'
        }))
      }
    })
  })
}
