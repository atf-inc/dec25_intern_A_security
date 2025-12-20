import { NextRequest, NextResponse } from 'next/server'
import { readFile } from 'fs/promises'
import { join } from 'path'

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const file = searchParams.get('file') || 'test.txt'
  
  // VULNERABLE: Path traversal - no validation
  try {
    // Dangerous: Direct file access without path validation
    const filePath = join(process.cwd(), 'public', file)
    const content = await readFile(filePath, 'utf-8')
    
    return NextResponse.json({
      success: true,
      file: file,
      path: filePath,
      content: content,
      warning: 'VULNERABLE: Path traversal possible. Try: ?file=../../../etc/passwd'
    })
  } catch (error: any) {
    return NextResponse.json({
      error: 'File read error',
      message: error.message,
      file: file,
      warning: 'VULNERABLE: Path traversal attempted'
    }, { status: 500 })
  }
}

