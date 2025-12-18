/**
 * Database Migration Script
 * Initializes the SQLite database with all dummy users
 */

import sqlite3 from 'sqlite3'
import path from 'path'
import fs from 'fs'
import { dummyUsers } from '../data/dummy_users'

const DB_PATH = path.join(process.cwd(), 'data', 'shopvuln.db')
const DB_DIR = path.join(process.cwd(), 'data')

// Ensure data directory exists
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true })
  console.log('Created data directory:', DB_DIR)
}

console.log('Starting database migration...')
console.log('Database path:', DB_PATH)

// Create database connection
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Database connection error:', err)
    process.exit(1)
  } else {
    console.log('Connected to SQLite database')
  }
})

// Initialize database
db.serialize(() => {
  // Drop existing table if it exists (for clean migration)
  db.run(`DROP TABLE IF EXISTS users`, (err) => {
    if (err) {
      console.error('Error dropping users table:', err)
    } else {
      console.log('Dropped existing users table (if any)')
    }
  })

  // Create users table
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`, (err) => {
    if (err) {
      console.error('Error creating users table:', err)
      process.exit(1)
    } else {
      console.log('Created users table')
    }
  })

  // Insert all dummy users
  const stmt = db.prepare(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`)
  
  let insertedCount = 0
  let errorCount = 0

  dummyUsers.forEach((user) => {
    stmt.run(user.id, user.username, user.email, user.password, (err) => {
      if (err) {
        console.error(`Error inserting user ${user.username}:`, err.message)
        errorCount++
      } else {
        insertedCount++
        console.log(`✓ Inserted user: ${user.username} (ID: ${user.id})`)
      }
    })
  })
  
  stmt.finalize((err) => {
    if (err) {
      console.error('Error finalizing insert statement:', err)
      process.exit(1)
    } else {
      console.log('\n=== Migration Summary ===')
      console.log(`Total users to insert: ${dummyUsers.length}`)
      console.log(`Successfully inserted: ${insertedCount}`)
      console.log(`Errors: ${errorCount}`)
      
      // Verify the data
      db.get('SELECT COUNT(*) as count FROM users', (err, row: any) => {
        if (err) {
          console.error('Error verifying data:', err)
        } else {
          console.log(`\nDatabase now contains ${row.count} users`)
          
          // List all users
          db.all('SELECT id, username, email FROM users ORDER BY id', (err, rows: any) => {
            if (err) {
              console.error('Error fetching users:', err)
            } else {
              console.log('\n=== All Users in Database ===')
              rows.forEach((user: any) => {
                console.log(`ID: ${user.id}, Username: ${user.username}, Email: ${user.email}`)
              })
            }
            
            // Close database
            db.close((err) => {
              if (err) {
                console.error('Error closing database:', err)
                process.exit(1)
              } else {
                console.log('\n✓ Database migration completed successfully!')
                console.log(`Database file: ${DB_PATH}`)
                process.exit(0)
              }
            })
          })
        }
      })
    }
  })
})
