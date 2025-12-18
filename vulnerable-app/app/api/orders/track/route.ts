import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const trackingUrl = searchParams.get('url') || 'https://api.shipping.com/track'
  
  // VULNERABLE: SSRF - no URL validation
  try {
    const response = await fetch(trackingUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'ShopVuln/1.0'
      }
    })
    
    const text = await response.text()
    
    return NextResponse.json({
      success: true,
      trackingUrl: trackingUrl,
      status: response.status,
      response: text.substring(0, 500),
      warning: 'VULNERABLE: SSRF - can make requests to internal services. Try: ?url=http://localhost:22 or ?url=file:///etc/passwd'
    })
  } catch (error: any) {
    return NextResponse.json({
      error: 'Tracking request failed',
      message: error.message,
      trackingUrl: trackingUrl,
      warning: 'VULNERABLE: SSRF attempted'
    }, { status: 500 })
  }
}

