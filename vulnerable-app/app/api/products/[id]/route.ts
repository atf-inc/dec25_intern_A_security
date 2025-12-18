import { NextRequest, NextResponse } from 'next/server'
import sqlite3 from 'sqlite3'

const db = new sqlite3.Database(':memory:')

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const productId = params.id
  
  // VULNERABLE: SQL Injection
  return new Promise((resolve) => {
    const query = `SELECT * FROM products WHERE id = ${productId}`
    
    db.get(query, (err: any, row: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'Database error',
          message: err.message,
          query: query
        }, { status: 500 }))
      } else if (row) {
        resolve(NextResponse.json({
          product: row,
          query: query
        }))
      } else {
        resolve(NextResponse.json({
          error: 'Product not found',
          query: query
        }, { status: 404 }))
      }
    })
  })
}

