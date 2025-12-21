import { NextRequest, NextResponse } from 'next/server'
import getDatabase from '@/lib/db'

// Get reviews for a product
export async function GET(request: NextRequest): Promise<NextResponse> {
    const db = getDatabase()
    const searchParams = request.nextUrl.searchParams
    const productId = searchParams.get('product_id')

    return new Promise((resolve) => {
        const query = `
      SELECT r.*, u.username 
      FROM reviews r 
      JOIN users u ON r.user_id = u.id 
      WHERE r.product_id = ?
      ORDER BY r.created_at DESC
    `

        db.all(query, [productId], (err: any, rows: any) => {
            if (err) {
                resolve(NextResponse.json({ error: 'Database error' }, { status: 500 }))
            } else {
                resolve(NextResponse.json({ reviews: rows }))
            }
        })
    })
}

// Add a review - VULNERABLE to XSS (no sanitization)
export async function POST(request: NextRequest): Promise<NextResponse> {
    const db = getDatabase()
    const body = await request.json()
    const { product_id, user_id, rating, comment } = body

    return new Promise((resolve) => {
        // VULNERABLE: No sanitization of comment (XSS)
        db.run(
            'INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
            [product_id, user_id, rating, comment],
            function (err: any) {
                if (err) {
                    resolve(NextResponse.json({ error: 'Failed to add review' }, { status: 500 }))
                } else {
                    resolve(NextResponse.json({
                        success: true,
                        reviewId: this.lastID,
                        vulnerable: true,
                        hint: 'Comment is rendered without sanitization - try XSS payload'
                    }))
                }
            }
        )
    })
}
