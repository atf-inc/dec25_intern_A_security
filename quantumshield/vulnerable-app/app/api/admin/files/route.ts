import { NextRequest, NextResponse } from 'next/server'
import { readFile } from 'fs/promises'
import { join } from 'path'

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const file = searchParams.get('file') || 'test.txt'
  
  // VULNERABLE: Path traversal
  try {
    const filePath = join(process.cwd(), 'public', file)
    const content = await readFile(filePath, 'utf-8')
    
    return NextResponse.json({
      success: true,
      file: file,
      path: filePath,
      content: content,
      warning: 'VULNERABLE: Path traversal possible. Try: ?file=../../../package.json'
    })
  } catch (error: any) {
    return NextResponse.json({
      error: 'File read error',
      message: error.message,
      file: file
    }, { status: 500 })
  }
}

