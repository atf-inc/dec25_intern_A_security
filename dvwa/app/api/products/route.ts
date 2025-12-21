import { NextRequest, NextResponse } from 'next/server'
import getDatabase from '@/lib/db'

export async function GET(request: NextRequest): Promise<NextResponse> {
    const db = getDatabase()
    const searchParams = request.nextUrl.searchParams
    const search = searchParams.get('search')

    return new Promise((resolve) => {
        if (search) {
            // VULNERABLE: SQL Injection in search
            const query = `SELECT * FROM products WHERE name LIKE '%${search}%' OR description LIKE '%${search}%'`

            db.all(query, (err: any, rows: any) => {
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
                        vulnerable: true,
                        hint: 'Try: search=iPhone\' OR 1=1--'
                    }))
                }
            })
        } else {
            // Get all products
            db.all('SELECT * FROM products', (err: any, rows: any) => {
                if (err) {
                    resolve(NextResponse.json({ error: 'Database error' }, { status: 500 }))
                } else {
                    resolve(NextResponse.json({ products: rows }))
                }
            })
        }
    })
}
