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
    tags TEXT
  )`)
  
  db.run(`INSERT INTO products (name, description, price, category, image, stock, tags) VALUES 
    ('Laptop Pro', 'High-performance laptop for professionals', 1299.99, 'Electronics', '💻', 50, 'laptop,computer,work'),
    ('Smartphone X', 'Latest smartphone with advanced features', 899.99, 'Electronics', '📱', 100, 'phone,mobile,smartphone'),
    ('Wireless Headphones', 'Premium noise-cancelling headphones', 199.99, 'Audio', '🎧', 75, 'headphones,audio,wireless'),
    ('Smart Watch', 'Fitness tracking smartwatch', 349.99, 'Wearables', '⌚', 60, 'watch,fitness,smart'),
    ('Tablet Air', 'Lightweight tablet for work and play', 599.99, 'Electronics', '📱', 40, 'tablet,mobile'),
    ('Gaming Mouse', 'Precision gaming mouse', 79.99, 'Gaming', '🖱️', 200, 'mouse,gaming,computer')`)
})

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const q = searchParams.get('q') || ''
  const category = searchParams.get('category') || ''
  const minPrice = searchParams.get('minPrice') || ''
  const maxPrice = searchParams.get('maxPrice') || ''
  const sortBy = searchParams.get('sortBy') || 'name'
  const order = searchParams.get('order') || 'ASC'
  
  // VULNERABLE: SQL Injection in multiple parameters
  // VULNERABLE: Reflected XSS in search query
  return new Promise((resolve) => {
    let query = 'SELECT * FROM products WHERE 1=1'
    const params: any[] = []
    
    // VULNERABLE: Direct string concatenation - SQL Injection
    if (q) {
      query += ` AND (name LIKE '%${q}%' OR description LIKE '%${q}%' OR tags LIKE '%${q}%')`
    }
    
    if (category) {
      query += ` AND category = '${category}'`
    }
    
    if (minPrice) {
      query += ` AND price >= ${minPrice}`
    }
    
    if (maxPrice) {
      query += ` AND price <= ${maxPrice}`
    }
    
    // VULNERABLE: SQL Injection in ORDER BY
    query += ` ORDER BY ${sortBy} ${order}`
    
    db.all(query, params, (err: any, rows: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query,
          searchQuery: q,
          warning: 'VULNERABLE: SQL Injection and Reflected XSS! Try: ?q=<script>alert("XSS")</script> or ?q=test\' OR \'1\'=\'1'
        }, { status: 500 }))
      } else {
        // VULNERABLE: Reflected XSS - search query not sanitized
        resolve(NextResponse.json({
          products: rows,
          count: rows.length,
          query: query,
          searchQuery: q, // VULNERABLE: XSS - this will be reflected in response
          warning: 'VULNERABLE: SQL Injection and Reflected XSS in search!'
        }))
      }
    })
  })
}
