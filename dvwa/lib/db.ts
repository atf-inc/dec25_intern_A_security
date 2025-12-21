import sqlite3 from 'sqlite3'
import path from 'path'

const dbPath = path.join(process.cwd(), 'shop.db')
let db: sqlite3.Database | null = null

export function getDatabase(): sqlite3.Database {
    if (!db) {
        db = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                console.error('❌ Database connection error:', err)
            } else {
                console.log('✅ Connected to SQLite database')
                initializeDatabase()
            }
        })
    }
    return db
}

function initializeDatabase() {
    if (!db) return

    db.serialize(() => {
        // Users table
        db!.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      profile_pic TEXT DEFAULT '/default-avatar.png',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
            if (err) console.error('Error creating users table:', err)
        })

        // Products table
        db!.run(`CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      image TEXT,
      stock INTEGER DEFAULT 0
    )`, (err) => {
            if (err) console.error('Error creating products table:', err)
        })

        // Orders table
        db!.run(`CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      total REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (product_id) REFERENCES products(id)
    )`, (err) => {
            if (err) console.error('Error creating orders table:', err)
        })

        // Reviews table
        db!.run(`CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      rating INTEGER NOT NULL,
      comment TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (product_id) REFERENCES products(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`, (err) => {
            if (err) console.error('Error creating reviews table:', err)
            else seedData()
        })
    })
}

function seedData() {
    if (!db) return

    // Check if data already exists
    db.get('SELECT COUNT(*) as count FROM products', (err, row: any) => {
        if (err) {
            console.error('Error checking products:', err)
            return
        }

        if (row && row.count > 0) {
            console.log('📦 Database already seeded')
            return
        }

        console.log('🌱 Seeding database...')

        // Seed users
        const users = [
            { username: 'admin', email: 'admin@shop.com', password: 'admin123' },
            { username: 'john', email: 'john@example.com', password: 'password123' },
            { username: 'alice', email: 'alice@example.com', password: 'alice123' }
        ]

        users.forEach(user => {
            db!.run(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [user.username, user.email, user.password],
                (err) => {
                    if (err) console.error(`Error inserting user ${user.username}:`, err)
                }
            )
        })

        // Seed products
        const products = [
            { name: 'iPhone 15 Pro', description: 'Latest Apple smartphone with A17 chip', price: 999.99, image: '/products/iphone.jpg', stock: 50 },
            { name: 'Samsung Galaxy S24', description: 'Flagship Android phone with AI features', price: 899.99, image: '/products/samsung.jpg', stock: 45 },
            { name: 'MacBook Pro M3', description: 'Powerful laptop for professionals', price: 1999.99, image: '/products/macbook.jpg', stock: 30 },
            { name: 'Dell XPS 15', description: 'Premium Windows laptop', price: 1499.99, image: '/products/dell.jpg', stock: 25 },
            { name: 'AirPods Pro', description: 'Wireless earbuds with noise cancellation', price: 249.99, image: '/products/airpods.jpg', stock: 100 },
            { name: 'Sony WH-1000XM5', description: 'Industry-leading noise cancelling headphones', price: 399.99, image: '/products/sony.jpg', stock: 60 }
        ]

        products.forEach(product => {
            db!.run(
                'INSERT INTO products (name, description, price, image, stock) VALUES (?, ?, ?, ?, ?)',
                [product.name, product.description, product.price, product.image, product.stock],
                (err) => {
                    if (err) console.error(`Error inserting product ${product.name}:`, err)
                }
            )
        })

        // Seed some orders
        db!.run('INSERT INTO orders (user_id, product_id, quantity, total, status) VALUES (2, 1, 1, 999.99, "delivered")')
        db!.run('INSERT INTO orders (user_id, product_id, quantity, total, status) VALUES (3, 5, 2, 499.98, "shipped")')

        console.log('✅ Database seeded successfully')
    })
}

// Initialize database on module load
getDatabase()

export default getDatabase
