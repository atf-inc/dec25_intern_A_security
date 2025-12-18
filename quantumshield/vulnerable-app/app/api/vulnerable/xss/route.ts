import { NextRequest, NextResponse } from 'next/server'

// Store for stored XSS
let storedComments: Array<{id: number, comment: string, user: string}> = []
let commentId = 1

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const name = searchParams.get('name') || 'Guest'
  
  // VULNERABLE: Reflected XSS - no sanitization
  return NextResponse.json({
    message: `Hello, ${name}! Welcome to our site.`,
    raw: name,
    vulnerable: true,
    warning: 'This endpoint is vulnerable to XSS. Try: ?name=<script>alert("XSS")</script>'
  })
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { comment, user } = body
  
  // VULNERABLE: Stored XSS - no sanitization
  const newComment = {
    id: commentId++,
    comment: comment || '',
    user: user || 'Anonymous'
  }
  storedComments.push(newComment)
  
  return NextResponse.json({
    success: true,
    comment: newComment,
    allComments: storedComments,
    warning: 'Comments are stored without sanitization - vulnerable to stored XSS'
  })
}

