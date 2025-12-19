import { NextRequest, NextResponse } from 'next/server'
import { writeFile } from 'fs/promises'
import { join } from 'path'
import { exec } from 'child_process'
import { promisify } from 'util'

const execAsync = promisify(exec)

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const file = formData.get('file') as File
    const action = formData.get('action') as string || 'upload'
    
    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    }
    
    const bytes = await file.arrayBuffer()
    const buffer = Buffer.from(bytes)
    
    // VULNERABLE: No file validation
    const uploadPath = join(process.cwd(), 'public', 'uploads', file.name)
    await writeFile(uploadPath, buffer)
    
    let result: any = {
      success: true,
      filename: file.name,
      size: file.size,
      type: file.type,
      path: uploadPath,
      warning: 'VULNERABLE: File uploaded without validation!'
    }
    
    // VULNERABLE: Command injection if action is 'process'
    if (action === 'process') {
      // Dangerous: Execute command with filename
      const command = `file "${uploadPath}"`
      try {
        const { stdout } = await execAsync(command)
        result.fileInfo = stdout
        result.command = command
        result.warning = 'VULNERABLE: Command injection possible in file processing!'
      } catch (error: any) {
        result.fileInfoError = error.message
      }
    }
    
    return NextResponse.json(result)
  } catch (error: any) {
    return NextResponse.json({
      error: 'Upload failed',
      message: error.message
    }, { status: 500 })
  }
}

