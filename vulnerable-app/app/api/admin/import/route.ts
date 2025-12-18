import { NextRequest, NextResponse } from 'next/server'
const { parseString } = require('xml2js')

export async function POST(request: NextRequest) {
  const contentType = request.headers.get('content-type') || ''
  const body = await request.text()
  
  // VULNERABLE: XXE and Insecure Deserialization
  if (contentType.includes('application/xml') || contentType.includes('text/xml')) {
    // XXE vulnerability
    return new Promise((resolve) => {
      parseString(body, {
        explicitArray: false,
        ignoreAttrs: false
      }, (err: any, result: any) => {
        if (err) {
          resolve(NextResponse.json({
            error: 'XML parsing failed',
            message: err.message,
            warning: 'VULNERABLE: XXE possible'
          }, { status: 400 }))
        } else {
          resolve(NextResponse.json({
            success: true,
            parsed: result,
            warning: 'VULNERABLE: XXE - external entities are processed!'
          }))
        }
      })
    })
  } else {
    // Insecure deserialization (JSON with eval)
    try {
      // DANGEROUS: Using eval for deserialization
      const data = eval(`(${body})`)
      
      return NextResponse.json({
        success: true,
        deserialized: data,
        warning: 'VULNERABLE: Insecure deserialization using eval! Can execute arbitrary code!'
      })
    } catch (error: any) {
      return NextResponse.json({
        error: 'Deserialization failed',
        message: error.message,
        warning: 'VULNERABLE: Deserialization error - code execution possible'
      }, { status: 400 })
    }
  }
}

