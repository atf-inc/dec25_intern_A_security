import { NextRequest, NextResponse } from 'next/server'
import { writeFile } from 'fs/promises'
import { join } from 'path'

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const file = formData.get('file') as File
    
    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    }
    
    // VULNERABLE: No file type validation, no size limit, no sanitization
    const bytes = await file.arrayBuffer()
    const buffer = Buffer.from(bytes)
    
    // Dangerous: Save file with original name, no validation
    const uploadPath = join(process.cwd(), 'public', 'uploads', file.name)
    await writeFile(uploadPath, buffer)
    
    return NextResponse.json({
      success: true,
      filename: file.name,
      size: file.size,
      type: file.type,
      path: uploadPath,
      warning: 'VULNERABLE: File uploaded without validation. Malicious files can be uploaded!'
    })
  } catch (error: any) {
    return NextResponse.json({
      error: 'Upload failed',
      message: error.message
    }, { status: 500 })
  }
}

