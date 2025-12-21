import { NextRequest, NextResponse } from 'next/server'
import getDatabase from '@/lib/db'

// VULNERABLE: IDOR - No authorization check
export async function GET(request: NextRequest): Promise<NextResponse> {
    const db = getDatabase()
    const searchParams = request.nextUrl.searchParams
    const userId = searchParams.get('user_id')

    return new Promise((resolve) => {
        const query = `
      SELECT o.*, p.name as product_name
      FROM orders o
      JOIN products p ON o.product_id = p.id
      WHERE o.user_id = ?
      ORDER BY o.created_at DESC
    `

        db.all(query, [userId], (err: any, rows: any) => {
            if (err) {
                resolve(NextResponse.json({ error: 'Database error' }, { status: 500 }))
            } else {
                resolve(NextResponse.json({
                    orders: rows,
                    vulnerable: true,
                    hint: 'IDOR: No authorization check - you can view any user\'s orders!'
                }))
            }
        })
    })
}
