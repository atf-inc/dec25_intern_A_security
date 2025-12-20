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
    stock INTEGER
  )`)
  
  db.run(`INSERT INTO products (name, description, price, category, image, stock) VALUES 
    ('Laptop Pro', 'High-performance laptop for professionals', 1299.99, 'Electronics', '💻', 50),
    ('Smartphone X', 'Latest smartphone with advanced features', 899.99, 'Electronics', '📱', 100),
    ('Wireless Headphones', 'Premium noise-cancelling headphones', 199.99, 'Audio', '🎧', 75),
    ('Smart Watch', 'Fitness tracking smartwatch', 349.99, 'Wearables', '⌚', 60),
    ('Tablet Air', 'Lightweight tablet for work and play', 599.99, 'Electronics', '📱', 40),
    ('Gaming Mouse', 'Precision gaming mouse', 79.99, 'Gaming', '🖱️', 200),
    ('Mechanical Keyboard', 'RGB mechanical keyboard', 149.99, 'Gaming', '⌨️', 150),
    ('Webcam HD', '1080p HD webcam for video calls', 89.99, 'Electronics', '📹', 80),
    ('USB-C Hub', 'Multi-port USB-C hub', 49.99, 'Accessories', '🔌', 200),
    ('Wireless Charger', 'Fast wireless charging pad', 39.99, 'Accessories', '🔋', 180),
    ('Bluetooth Speaker', 'Portable Bluetooth speaker', 79.99, 'Audio', '🔊', 120),
    ('External SSD', '1TB external SSD drive', 129.99, 'Storage', '💾', 90),
    ('Gaming Chair', 'Ergonomic gaming chair', 299.99, 'Furniture', '🪑', 45),
    ('Monitor 4K', '27-inch 4K monitor', 399.99, 'Electronics', '🖥️', 60),
    ('Gaming Headset', '7.1 surround sound headset', 129.99, 'Gaming', '🎮', 100)`)
})

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const search = searchParams.get('search') || ''
  const category = searchParams.get('category') || ''
  const minPrice = searchParams.get('minPrice') || ''
  const maxPrice = searchParams.get('maxPrice') || ''
  
  // VULNERABLE: SQL Injection in search and filters
  return new Promise((resolve) => {
    let query = 'SELECT * FROM products WHERE 1=1'
    const params: any[] = []
    
    // VULNERABLE: Direct string concatenation
    if (search) {
      query += ` AND (name LIKE '%${search}%' OR description LIKE '%${search}%')`
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
    
    db.all(query, params, (err: any, rows: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query
        }, { status: 500 }))
      } else {
        resolve(NextResponse.json({
          products: rows,
          query: query,
          warning: 'VULNERABLE: SQL injection possible in search/filters'
        }))
      }
    })
  })
}

