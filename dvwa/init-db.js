const sqlite3 = require('sqlite3').verbose()
const path = require('path')

const dbPath = path.join(__dirname, 'shop.db')
const db = new sqlite3.Database(dbPath)

console.log('🔧 Initializing database...')

db.serialize(() => {
    // Create tables
    db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    profile_pic TEXT DEFAULT '/default-avatar.png',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`)

    db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    image TEXT,
    stock INTEGER DEFAULT 0
  )`)

    db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    total REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`)

    db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL,
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`)

    // Check if we need to seed
    db.get('SELECT COUNT(*) as count FROM products', (err, row) => {
        if (err || (row && row.count > 0)) {
            console.log('📦 Database already has data')
            db.close()
            return
        }

        console.log('🌱 Seeding database...')

        // Seed users
        const stmt1 = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
        stmt1.run('admin', 'admin@shop.com', 'admin123')
        stmt1.run('john', 'john@example.com', 'password123')
        stmt1.run('alice', 'alice@example.com', 'alice123')
        stmt1.finalize()

        // Seed products
        const stmt2 = db.prepare('INSERT INTO products (name, description, price, image, stock) VALUES (?, ?, ?, ?, ?)')
        stmt2.run('iPhone 15 Pro', 'Latest Apple smartphone with A17 chip', 999.99, '/products/iphone.jpg', 50)
        stmt2.run('Samsung Galaxy S24', 'Flagship Android phone with AI features', 899.99, '/products/samsung.jpg', 45)
        stmt2.run('MacBook Pro M3', 'Powerful laptop for professionals', 1999.99, '/products/macbook.jpg', 30)
        stmt2.run('Dell XPS 15', 'Premium Windows laptop', 1499.99, '/products/dell.jpg', 25)
        stmt2.run('AirPods Pro', 'Wireless earbuds with noise cancellation', 249.99, '/products/airpods.jpg', 100)
        stmt2.run('Sony WH-1000XM5', 'Industry-leading noise cancelling headphones', 399.99, '/products/sony.jpg', 60)
        stmt2.finalize()

        // Seed orders
        const stmt3 = db.prepare('INSERT INTO orders (user_id, product_id, quantity, total, status) VALUES (?, ?, ?, ?, ?)')
        stmt3.run(2, 1, 1, 999.99, 'delivered')
        stmt3.run(3, 5, 2, 499.98, 'shipped')
        stmt3.finalize()

        console.log('✅ Database initialized successfully!')
        db.close()
    })
})
