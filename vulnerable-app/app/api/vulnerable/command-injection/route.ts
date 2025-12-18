import { NextRequest, NextResponse } from 'next/server'
import { exec } from 'child_process'
import { promisify } from 'util'

const execAsync = promisify(exec)

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const host = searchParams.get('host') || 'localhost'
  
  // VULNERABLE: Command injection - no sanitization
  return new Promise((resolve) => {
    // Dangerous: Direct command execution
    const command = `ping -c 4 ${host}`
    
    exec(command, (error, stdout, stderr) => {
      if (error) {
        resolve(NextResponse.json({
          error: 'Command execution failed',
          message: error.message,
          command: command,
          stderr: stderr,
          warning: 'VULNERABLE: Command injection possible. Try: ?host=localhost; cat /etc/passwd'
        }, { status: 500 }))
      } else {
        resolve(NextResponse.json({
          success: true,
          command: command,
          output: stdout,
          warning: 'VULNERABLE: Command injection possible'
        }))
      }
    })
  })
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { command } = body
  
  // VULNERABLE: Direct command execution from user input
  return new Promise((resolve) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        resolve(NextResponse.json({
          error: 'Command execution failed',
          message: error.message,
          command: command,
          stderr: stderr
        }, { status: 500 }))
      } else {
        resolve(NextResponse.json({
          success: true,
          command: command,
          output: stdout
        }))
      }
    })
  })
}

