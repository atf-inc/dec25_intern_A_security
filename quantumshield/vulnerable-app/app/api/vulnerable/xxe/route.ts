import { NextRequest, NextResponse } from 'next/server'
const { parseString } = require('xml2js')

export async function POST(request: NextRequest) {
  const body = await request.text()
  
  // VULNERABLE: XXE - no XML validation
  return new Promise((resolve) => {
    parseString(body, {
      // VULNERABLE: External entities enabled
      explicitArray: false,
      ignoreAttrs: false
    }, (err: any, result: any) => {
      if (err) {
        resolve(NextResponse.json({
          error: 'XML parsing failed',
          message: err.message,
          warning: 'VULNERABLE: XXE possible. Try including external entities'
        }, { status: 400 }))
      } else {
        resolve(NextResponse.json({
          success: true,
          parsed: result,
          warning: 'VULNERABLE: XXE possible. External entities are processed!'
        }))
      }
    })
  })
}

