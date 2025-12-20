import { NextRequest, NextResponse } from 'next/server'

// In-memory storage for reviews
let reviews: Array<{
  id: number,
  productId: number,
  author: string,
  rating: number,
  comment: string,
  date: string
}> = []
let reviewId = 1

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const productId = searchParams.get('productId')
  
  const productReviews = productId 
    ? reviews.filter(r => r.productId === parseInt(productId))
    : reviews
  
  return NextResponse.json({
    reviews: productReviews,
    warning: 'VULNERABLE: Stored XSS in reviews - comments are not sanitized!'
  })
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { productId, author, rating, comment } = body
  
  // VULNERABLE: Stored XSS - no sanitization
  const review = {
    id: reviewId++,
    productId: parseInt(productId),
    author: author || 'Anonymous',
    rating: parseInt(rating) || 5,
    comment: comment || '',
    date: new Date().toISOString()
  }
  
  reviews.push(review)
  
  return NextResponse.json({
    success: true,
    review: review,
    warning: 'VULNERABLE: Review stored without sanitization - XSS possible!'
  })
}

