import { NextRequest, NextResponse } from 'next/server'

// Mock database
const users: Record<number, { id: number, name: string, email: string, balance: number }> = {
  1: { id: 1, name: 'Admin User', email: 'admin@shopvuln.com', balance: 10000.00 },
  2: { id: 2, name: 'John Doe', email: 'john.doe@email.com', balance: 1250.50 },
  3: { id: 3, name: 'Jane Smith', email: 'jane.smith@email.com', balance: 2850.75 },
  4: { id: 4, name: 'Mike Wilson', email: 'mike.wilson@email.com', balance: 750.25 },
  5: { id: 5, name: 'Sarah Jones', email: 'sarah.jones@email.com', balance: 1950.00 },
  6: { id: 6, name: 'David Brown', email: 'david.brown@email.com', balance: 3200.50 },
  7: { id: 7, name: 'Emily Davis', email: 'emily.davis@email.com', balance: 450.00 },
  8: { id: 8, name: 'Chris Miller', email: 'chris.miller@email.com', balance: 1650.75 },
  9: { id: 9, name: 'Lisa Anderson', email: 'lisa.anderson@email.com', balance: 2750.25 },
  10: { id: 10, name: 'Robert Taylor', email: 'robert.taylor@email.com', balance: 850.50 },
  11: { id: 11, name: 'Amanda White', email: 'amanda.white@email.com', balance: 2100.00 },
  12: { id: 12, name: 'James Martin', email: 'james.martin@email.com', balance: 1450.75 },
  13: { id: 13, name: 'Jennifer Thomas', email: 'jennifer.thomas@email.com', balance: 3800.25 },
  14: { id: 14, name: 'William Jackson', email: 'william.jackson@email.com', balance: 950.00 },
  15: { id: 15, name: 'Michelle Harris', email: 'michelle.harris@email.com', balance: 2250.50 },
  16: { id: 16, name: 'Richard Clark', email: 'richard.clark@email.com', balance: 1750.75 },
  17: { id: 17, name: 'Patricia Lewis', email: 'patricia.lewis@email.com', balance: 3100.25 },
  18: { id: 18, name: 'Daniel Robinson', email: 'daniel.robinson@email.com', balance: 550.00 },
  19: { id: 19, name: 'Linda Walker', email: 'linda.walker@email.com', balance: 2650.50 },
  20: { id: 20, name: 'Mark Young', email: 'mark.young@email.com', balance: 1350.75 }
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const userId = parseInt(searchParams.get('id') || '1')
  
  // VULNERABLE: IDOR - no authorization check
  const user = users[userId]
  
  if (user) {
    return NextResponse.json({
      success: true,
      user: user,
      warning: 'VULNERABLE: IDOR - can access any user by changing ID. Try: ?id=1, ?id=2, ?id=3'
    })
  }
  
  return NextResponse.json({
    error: 'User not found',
    userId: userId
  }, { status: 404 })
}

export async function PUT(request: NextRequest) {
  const body = await request.json()
  const { userId, balance } = body
  
  // VULNERABLE: IDOR - can modify any user's data
  if (users[userId]) {
    users[userId].balance = balance
    
    return NextResponse.json({
      success: true,
      message: 'Balance updated',
      user: users[userId],
      warning: 'VULNERABLE: IDOR - can modify any user without authorization!'
    })
  }
  
  return NextResponse.json({
    error: 'User not found'
  }, { status: 404 })
}

