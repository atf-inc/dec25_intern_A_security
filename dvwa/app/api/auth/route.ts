import { NextRequest, NextResponse } from 'next/server'
import getDatabase from '@/lib/db'

// Login endpoint - VULNERABLE to SQL Injection
export async function POST(request: NextRequest) {
    const db = getDatabase()
    const body = await request.json()
    const { username, password, action } = body

    if (action === 'register') {
        // Simple registration (not vulnerable)
        return new Promise((resolve) => {
            db.run(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [username, body.email, password],
                function (err: any) {
                    if (err) {
                        resolve(NextResponse.json({ error: 'User already exists' }, { status: 400 }))
                    } else {
                        resolve(NextResponse.json({
                            success: true,
                            userId: this.lastID,
                            message: 'Registration successful'
                        }))
                    }
                }
            )
        })
    }

    // VULNERABLE: SQL Injection in login
    return new Promise((resolve) => {
        const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`

        db.all(query, (err: any, rows: any) => {
            if (err) {
                resolve(NextResponse.json({
                    error: 'Database error',
                    message: err.message,
                    query: query
                }, { status: 500 }))
            } else {
                if (rows.length > 0) {
                    resolve(NextResponse.json({
                        success: true,
                        user: rows[0],
                        query: query,
                        vulnerable: true,
                        hint: 'Try: username=admin\' OR 1=1-- password=anything'
                    }))
                } else {
                    resolve(NextResponse.json({
                        success: false,
                        message: 'Invalid credentials',
                        query: query
                    }, { status: 401 }))
                }
            }
        })
    })
}
