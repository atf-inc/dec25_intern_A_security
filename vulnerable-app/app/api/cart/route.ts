import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'

// In-memory cart storage (vulnerable - no proper session management)
let carts: Record<string, any[]> = {}

export async function GET(request: NextRequest) {
  const cookieStore = cookies()
  const userId = cookieStore.get('user_id')?.value || 'guest'
  
  // VULNERABLE: IDOR - can access any user's cart by changing user_id cookie
  const cart = carts[userId] || []
  
  return NextResponse.json({
    cart: cart,
    total: cart.reduce((sum, item) => sum + (item.price * item.quantity), 0),
    warning: 'VULNERABLE: IDOR - can access other users\' carts by changing user_id cookie'
  })
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { productId, quantity, price, name } = body
  
  const cookieStore = cookies()
  const userId = cookieStore.get('user_id')?.value || 'guest'
  
  if (!carts[userId]) {
    carts[userId] = []
  }
  
  const existingItem = carts[userId].find(item => item.productId === productId)
  if (existingItem) {
    existingItem.quantity += quantity || 1
  } else {
    carts[userId].push({
      productId,
      name,
      price,
      quantity: quantity || 1
    })
  }
  
  return NextResponse.json({
    success: true,
    cart: carts[userId]
  })
}

export async function DELETE(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const productId = searchParams.get('productId')
  
  const cookieStore = cookies()
  const userId = cookieStore.get('user_id')?.value || 'guest'
  
  if (carts[userId]) {
    carts[userId] = carts[userId].filter(item => item.productId !== productId)
  }
  
  return NextResponse.json({
    success: true,
    cart: carts[userId] || []
  })
}

