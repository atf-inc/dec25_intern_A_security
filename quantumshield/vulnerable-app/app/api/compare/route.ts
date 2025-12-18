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
    specs TEXT
  )`)
  
  db.run(`INSERT INTO products (name, description, price, category, image, stock, specs) VALUES 
    ('Laptop Pro', 'High-performance laptop', 1299.99, 'Electronics', '💻', 50, '{"cpu":"Intel i7","ram":"16GB","storage":"512GB SSD"}'),
    ('Smartphone X', 'Latest smartphone', 899.99, 'Electronics', '📱', 100, '{"screen":"6.5 inch","storage":"128GB","camera":"48MP"}'),
    ('Wireless Headphones', 'Premium headphones', 199.99, 'Audio', '🎧', 75, '{"battery":"30h","noise_cancelling":true}')`)
})

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const productIds = searchParams.get('ids') || ''
  
  // VULNERABLE: SQL Injection in product IDs
  const ids = productIds.split(',').map(id => id.trim())
  
  return new Promise((resolve) => {
    // VULNERABLE: Direct string concatenation - SQL Injection
    const query = `SELECT * FROM products WHERE id IN (${ids.join(',')})`
    
    db.all(query, [], (err: any, rows: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query,
          warning: 'VULNERABLE: SQL Injection - try: ?ids=1) OR 1=1--'
        }, { status: 500 }))
      } else {
        resolve(NextResponse.json({
          products: rows,
          query: query,
          warning: 'VULNERABLE: SQL Injection in product comparison!'
        }))
      }
    })
  })
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { productIds, comparisonName } = body
  
  // VULNERABLE: Stored XSS in comparison name
  // No sanitization - XSS possible
  const comparison = {
    id: Math.floor(Math.random() * 1000000),
    name: comparisonName || 'My Comparison',
    productIds: productIds || [],
    createdAt: new Date().toISOString()
  }
  
  return NextResponse.json({
    success: true,
    comparison: comparison,
    warning: 'VULNERABLE: Stored XSS - comparison name is not sanitized! Try: {"comparisonName":"<script>alert(\'XSS\')</script>","productIds":[1,2]}'
  })
}
