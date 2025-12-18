import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'
import sqlite3 from 'sqlite3'

// In-memory wishlist storage (vulnerable - no proper session management)
let wishlists: Record<string, any[]> = {}

export async function GET(request: NextRequest) {
  const cookieStore = cookies()
  const userId = cookieStore.get('user_id')?.value || 'guest'
  const targetUserId = request.nextUrl.searchParams.get('userId') || userId
  
  // VULNERABLE: IDOR - can access any user's wishlist by changing userId parameter
  const wishlist = wishlists[targetUserId] || []
  
  return NextResponse.json({
    wishlist: wishlist,
    userId: targetUserId,
    warning: 'VULNERABLE: IDOR - can access other users\' wishlists by changing userId parameter. Try: ?userId=admin'
  })
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { productId, name, price, image } = body
  
  const cookieStore = cookies()
  const userId = cookieStore.get('user_id')?.value || 'guest'
  const targetUserId = body.userId || userId
  
  // VULNERABLE: IDOR - can add items to any user's wishlist
  if (!wishlists[targetUserId]) {
    wishlists[targetUserId] = []
  }
  
  const existingItem = wishlists[targetUserId].find(item => item.productId === productId)
  if (!existingItem) {
    wishlists[targetUserId].push({
      productId,
      name,
      price,
      image,
      addedAt: new Date().toISOString()
    })
  }
  
  return NextResponse.json({
    success: true,
    wishlist: wishlists[targetUserId],
    warning: 'VULNERABLE: IDOR - can modify any user\'s wishlist!'
  })
}

export async function DELETE(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const productId = searchParams.get('productId')
  const targetUserId = searchParams.get('userId')
  
  const cookieStore = cookies()
  const userId = cookieStore.get('user_id')?.value || 'guest'
  const userIdToUse = targetUserId || userId
  
  // VULNERABLE: IDOR - can delete items from any user's wishlist
  if (wishlists[userIdToUse]) {
    wishlists[userIdToUse] = wishlists[userIdToUse].filter(item => item.productId !== productId)
  }
  
  return NextResponse.json({
    success: true,
    wishlist: wishlists[userIdToUse] || [],
    warning: 'VULNERABLE: IDOR - can delete items from any user\'s wishlist!'
  })
}
