import { NextResponse, NextRequest } from 'next/server'

// WAF Integration Configuration
const WAF_ENABLED = process.env.WAF_ENABLED === 'true'
const WAF_API_URL = process.env.WAF_API_URL || 'http://localhost:8000'
const WAF_API_ENDPOINT = process.env.WAF_API_ENDPOINT || '/api/waf/process'
const WAF_API_TIMEOUT = parseInt(process.env.WAF_API_TIMEOUT || '5000', 10)

// WAF API Client
async function processWAFRequest(requestData: any): Promise<any> {
  if (!WAF_ENABLED) {
    return {
      allowed: true,
      violations: [],
      action: 'allow',
      reason: 'WAF disabled'
    }
  }

  try {
    const url = `${WAF_API_URL}${WAF_API_ENDPOINT}`
    
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), WAF_API_TIMEOUT)
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestData),
      signal: controller.signal
    })
    
    clearTimeout(timeoutId)
    
    if (!response.ok) {
      console.error(`[WAF] API returned error: ${response.status} ${response.statusText}`)
      // On WAF service error, allow request but log warning
      return {
        allowed: true,
        violations: [],
        action: 'allow',
        reason: 'WAF service error - allowing request',
        warning: true
      }
    }
    
    const result = await response.json()
    return result
  } catch (error: any) {
    if (error.name === 'AbortError') {
      console.error('[WAF] Request timeout - WAF service did not respond in time')
    } else {
      console.error('[WAF] Error calling WAF API:', error.message)
    }
    
    // On error, allow request but log warning
    return {
      allowed: true,
      violations: [],
      action: 'allow',
      reason: 'WAF service unavailable - allowing request',
      warning: true
    }
  }
}

if (WAF_ENABLED) {
  console.log('[WAF] WAF protection enabled')
  console.log(`[WAF] API URL: ${WAF_API_URL}${WAF_API_ENDPOINT}`)
  console.log('[WAF] Make sure WAF API service is running: python waf-api-service.py')
} else {
  console.log('[WAF] WAF is disabled - running in vulnerable mode')
}

export async function middleware(request: NextRequest) {
  // If WAF is enabled, check the request
  if (WAF_ENABLED) {
    try {
      // Extract request data
      const url = new URL(request.url)
      const headers: Record<string, string> = {}
      request.headers.forEach((value, key) => {
        headers[key] = value
      })
      
      // Get request body if available
      let body = ''
      let bodyParams: Record<string, any> = {}
      
      try {
        // For GET requests, body is in query params
        if (request.method === 'GET') {
          body = url.searchParams.toString()
          // Also extract query params as body_params for GET requests
          url.searchParams.forEach((value, key) => {
            bodyParams[key] = value
          })
        } else if (request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH') {
          // Try to read body (Note: Next.js middleware has limitations with body reading)
          // In production, you might need to use a different approach
          const clonedRequest = request.clone()
          try {
            const bodyText = await clonedRequest.text()
            body = bodyText
            // Try to parse as JSON
            try {
              bodyParams = JSON.parse(bodyText)
            } catch {
              // Not JSON, try URL encoded
              try {
                const params = new URLSearchParams(bodyText)
                params.forEach((value, key) => {
                  bodyParams[key] = value
                })
              } catch {
                // Not URL encoded either - use raw body
                if (bodyText) {
                  bodyParams['_raw'] = bodyText
                }
              }
            }
          } catch {
            // Body not available
          }
        }
      } catch (e) {
        // Body not available in middleware
        console.error('[WAF] Error reading body:', e)
      }
      
      // Also include query params in body for comprehensive checking
      url.searchParams.forEach((value, key) => {
        if (!bodyParams[key]) {
          bodyParams[key] = value
        }
      })
      
      // Extract source IP
      const srcIp = request.headers.get('x-forwarded-for')?.split(',')[0].trim() || 
                    request.headers.get('x-real-ip') || 
                    request.ip || 
                    '127.0.0.1'
      
      // Combine all parameters for comprehensive checking
      const allParams: Record<string, any> = {}
      url.searchParams.forEach((value, key) => {
        allParams[key] = value
      })
      Object.assign(allParams, bodyParams)
      
      const requestData = {
        method: request.method,
        uri: url.pathname,
        headers: headers,
        body: body,
        query_params: Object.fromEntries(url.searchParams),
        body_params: bodyParams,
        all_params: allParams, // Combined params for easier checking
        src_ip: srcIp,
        timestamp: new Date().toISOString()
      }
      
      // Log request for debugging
      if (process.env.NODE_ENV === 'development') {
        console.log(`[WAF] Checking request: ${request.method} ${url.pathname}`)
        if (Object.keys(allParams).length > 0) {
          console.log(`[WAF] Parameters:`, JSON.stringify(allParams, null, 2))
        }
      }
      
      // Process through WAF API
      const result = await processWAFRequest(requestData)
      
      if (!result.allowed) {
        console.log(`[WAF] Request blocked: ${result.reason}`)
        console.log(`[WAF] Violations:`, JSON.stringify(result.violations, null, 2))
        console.log(`[WAF] Request: ${request.method} ${url.pathname}`)
        console.log(`[WAF] Source IP: ${srcIp}`)
        
        // Extract attack type from violations
        const attackTypes = new Set<string>()
        result.violations?.forEach((v: any) => {
          if (v.type === 'sql_injection') {
            attackTypes.add('SQL Injection')
          } else if (v.type === 'xss') {
            attackTypes.add('XSS (Cross-Site Scripting)')
          } else if (v.type === 'command_injection') {
            attackTypes.add('Command Injection')
          } else if (v.type === 'path_traversal') {
            attackTypes.add('Path Traversal')
          } else if (v.type === 'ssrf') {
            attackTypes.add('SSRF (Server-Side Request Forgery)')
          } else if (v.type === 'xxe') {
            attackTypes.add('XXE (XML External Entity)')
          } else if (v.type === 'csrf') {
            attackTypes.add('CSRF (Cross-Site Request Forgery)')
          } else if (v.type === 'idor') {
            attackTypes.add('IDOR (Insecure Direct Object Reference)')
          } else if (v.type === 'file_upload') {
            attackTypes.add('Malicious File Upload')
          } else if (v.type === 'deserialization') {
            attackTypes.add('Insecure Deserialization')
          } else {
            attackTypes.add('Malicious Activity')
          }
        })
        
        // Create user-friendly message
        const attackNames = Array.from(attackTypes)
        let attackName = 'Malicious Activity'
        if (attackNames.length === 1) {
          attackName = attackNames[0]
        } else if (attackNames.length > 1) {
          attackName = attackNames.join(' and ')
        }
        
        // Return clean, user-friendly response
        return NextResponse.json(
          {
            message: `Ohh you are trying to ${attackName}. You are detected by firewall. Better luck next time!`,
            blocked: true
          },
          { status: 403 }
        )
      }
      
      if (result.warning) {
        console.warn(`[WAF] Warning: ${result.reason}`)
      }
    } catch (error: any) {
      console.error('[WAF] Error processing request:', error)
      // Continue if WAF fails - don't block legitimate traffic
    }
  }
  
  return NextResponse.next()
}

export const config = {
  matcher: [
    '/api/:path*',
    '/vulnerable/:path*',
    '/search',
    '/login',
    '/upload',
    '/admin/:path*'
  ]
}

