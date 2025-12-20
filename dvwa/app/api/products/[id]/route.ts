import { NextRequest, NextResponse } from 'next/server'
import getDatabase from '@/lib/db'

export async function GET(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    const db = getDatabase()
    const { id } = await params

    return new Promise((resolve) => {
        db.get('SELECT * FROM products WHERE id = ?', [id], (err: any, row: any) => {
            if (err) {
                resolve(NextResponse.json({ error: 'Database error', message: err.message }, { status: 500 }))
            } else if (!row) {
                resolve(NextResponse.json({ error: 'Product not found' }, { status: 404 }))
            } else {
                resolve(NextResponse.json({ product: row }))
            }
        })
    })
}
