import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const url = searchParams.get('url') || 'https://example.com'
  
  // VULNERABLE: SSRF - no URL validation
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'VulnerableApp/1.0'
      }
    })
    
    const text = await response.text()
    
    return NextResponse.json({
      success: true,
      url: url,
      status: response.status,
      statusText: response.statusText,
      content: text.substring(0, 1000), // Limit display
      warning: 'VULNERABLE: SSRF possible. Try: ?url=http://localhost:22 or ?url=file:///etc/passwd'
    })
  } catch (error: any) {
    return NextResponse.json({
      error: 'Request failed',
      message: error.message,
      url: url,
      warning: 'VULNERABLE: SSRF attempted'
    }, { status: 500 })
  }
}

