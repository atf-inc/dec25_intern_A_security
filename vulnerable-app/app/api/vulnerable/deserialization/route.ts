import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const body = await request.text()
  
  // VULNERABLE: Insecure deserialization - using eval (very dangerous!)
  try {
    // DANGEROUS: Direct eval of user input
    const data = eval(`(${body})`)
    
    return NextResponse.json({
      success: true,
      deserialized: data,
      warning: 'VULNERABLE: Insecure deserialization using eval! This can execute arbitrary code!'
    })
  } catch (error: any) {
    return NextResponse.json({
      error: 'Deserialization failed',
      message: error.message,
      warning: 'VULNERABLE: Deserialization error - code execution possible'
    }, { status: 400 })
  }
}

