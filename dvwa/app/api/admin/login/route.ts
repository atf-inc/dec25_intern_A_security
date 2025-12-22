
import { NextResponse } from 'next/server'
import getDatabase from '@/lib/db'

export async function POST(request: Request) {
    try {
        const body = await request.json()
        const { username, password } = body

        if (!username || !password) {
            return NextResponse.json(
                { success: false, message: 'Missing credentials' },
                { status: 400 }
            )
        }

        const db = getDatabase()

        // VULNERABILITY: SQL Injection
        // Intentionally using string concatenation instead of parameterized queries
        const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`

        console.log(`[VULNERABLE SQL] Executing: ${query}`)

        // Wrap callback-based sqlite3 in a Promise AND await it
        const response = await new Promise<NextResponse>((resolve) => {
            db.get(query, (err: any, row: any) => {
                if (err) {
                    // VULNERABILITY: Verbose error messages
                    resolve(NextResponse.json(
                        { success: false, message: 'Database Error: ' + err.message },
                        { status: 500 }
                    ))
                } else {
                    if (row) {
                        resolve(NextResponse.json({
                            success: true,
                            username: row.username,
                            role: 'admin', // Assume admin for this vulnerable endpoint
                            message: 'Login successful'
                        }))
                    } else {
                        resolve(NextResponse.json(
                            { success: false, message: 'Invalid credentials for ' + username },
                            { status: 401 }
                        ))
                    }
                }
            })
        })

        return response

    } catch (error) {
        return NextResponse.json(
            { success: false, message: 'Internal Server Error' },
            { status: 500 }
        )
    }
}
