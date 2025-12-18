import { NextRequest, NextResponse } from 'next/server'
import { readFile } from 'fs/promises'
import { join } from 'path'

export async function GET(request: NextRequest) {
  // VULNERABLE: Security Misconfiguration - exposes sensitive configuration
  // VULNERABLE: Path Traversal
  const searchParams = request.nextUrl.searchParams
  const configFile = searchParams.get('file') || 'package.json'
  
  try {
    // VULNERABLE: No path validation - can read any file
    const filePath = join(process.cwd(), configFile)
    const content = await readFile(filePath, 'utf-8')
    
    let parsed: any = {}
    try {
      parsed = JSON.parse(content)
    } catch {
      // Not JSON, return as text
    }
    
    return NextResponse.json({
      success: true,
      file: configFile,
      path: filePath,
      content: parsed || content,
      warning: 'VULNERABLE: Security Misconfiguration - sensitive config exposed! Path traversal possible. Try: ?file=../.env or ?file=../quantumshield/config/settings.json'
    })
  } catch (error: any) {
    return NextResponse.json({
      error: 'Config read error',
      message: error.message,
      file: configFile,
      warning: 'VULNERABLE: Path traversal attempted!'
    }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { setting, value } = body
  
  // VULNERABLE: Security Misconfiguration - allows runtime config changes
  // VULNERABLE: No authentication/authorization
  // VULNERABLE: No input validation
  
  // In a real app, this would update configuration
  // Here we just simulate it
  
  return NextResponse.json({
    success: true,
    message: `Configuration updated: ${setting} = ${value}`,
    setting: setting,
    value: value,
    warning: 'VULNERABLE: Security Misconfiguration - can modify app settings without authentication!'
  })
}
