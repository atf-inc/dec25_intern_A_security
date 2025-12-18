import { NextRequest, NextResponse } from 'next/server'

// Mock user database
const users: Record<number, {
  id: number,
  username: string,
  email: string,
  balance: number,
  address: string,
  phone: string
}> = {
  1: { id: 1, username: 'admin', email: 'admin@shopvuln.com', balance: 10000.00, address: '123 Admin Street, Tech City, TC 12345', phone: '555-0100' },
  2: { id: 2, username: 'john_doe', email: 'john.doe@email.com', balance: 1250.50, address: '456 Oak Avenue, Springfield, SP 54321', phone: '555-0101' },
  3: { id: 3, username: 'jane_smith', email: 'jane.smith@email.com', balance: 2850.75, address: '789 Maple Drive, Riverside, RS 67890', phone: '555-0102' },
  4: { id: 4, username: 'mike_wilson', email: 'mike.wilson@email.com', balance: 750.25, address: '321 Pine Street, Mountain View, MV 11223', phone: '555-0103' },
  5: { id: 5, username: 'sarah_jones', email: 'sarah.jones@email.com', balance: 1950.00, address: '654 Elm Road, Lakeside, LS 44556', phone: '555-0104' },
  6: { id: 6, username: 'david_brown', email: 'david.brown@email.com', balance: 3200.50, address: '987 Cedar Lane, Hilltop, HT 77889', phone: '555-0105' },
  7: { id: 7, username: 'emily_davis', email: 'emily.davis@email.com', balance: 450.00, address: '147 Birch Court, Valley View, VV 33445', phone: '555-0106' },
  8: { id: 8, username: 'chris_miller', email: 'chris.miller@email.com', balance: 1650.75, address: '258 Willow Way, Greenfield, GF 55667', phone: '555-0107' },
  9: { id: 9, username: 'lisa_anderson', email: 'lisa.anderson@email.com', balance: 2750.25, address: '369 Spruce Street, Brookside, BS 66778', phone: '555-0108' },
  10: { id: 10, username: 'robert_taylor', email: 'robert.taylor@email.com', balance: 850.50, address: '741 Ash Avenue, Parkland, PL 88990', phone: '555-0109' },
  11: { id: 11, username: 'amanda_white', email: 'amanda.white@email.com', balance: 2100.00, address: '852 Cherry Boulevard, Woodside, WS 99001', phone: '555-0110' },
  12: { id: 12, username: 'james_martin', email: 'james.martin@email.com', balance: 1450.75, address: '963 Poplar Drive, Sunnydale, SD 11223', phone: '555-0111' },
  13: { id: 13, username: 'jennifer_thomas', email: 'jennifer.thomas@email.com', balance: 3800.25, address: '159 Magnolia Road, Fairview, FV 22334', phone: '555-0112' },
  14: { id: 14, username: 'william_jackson', email: 'william.jackson@email.com', balance: 950.00, address: '357 Cypress Lane, Clearwater, CW 33445', phone: '555-0113' },
  15: { id: 15, username: 'michelle_harris', email: 'michelle.harris@email.com', balance: 2250.50, address: '468 Sycamore Street, Milltown, MT 44556', phone: '555-0114' },
  16: { id: 16, username: 'richard_clark', email: 'richard.clark@email.com', balance: 1750.75, address: '579 Hickory Avenue, Riverview, RV 55667', phone: '555-0115' },
  17: { id: 17, username: 'patricia_lewis', email: 'patricia.lewis@email.com', balance: 3100.25, address: '680 Walnut Court, Hillcrest, HC 66778', phone: '555-0116' },
  18: { id: 18, username: 'daniel_robinson', email: 'daniel.robinson@email.com', balance: 550.00, address: '791 Chestnut Way, Meadowbrook, MB 77889', phone: '555-0117' },
  19: { id: 19, username: 'linda_walker', email: 'linda.walker@email.com', balance: 2650.50, address: '802 Beech Drive, Oakwood, OW 88990', phone: '555-0118' },
  20: { id: 20, username: 'mark_young', email: 'mark.young@email.com', balance: 1350.75, address: '913 Fir Boulevard, Pinecrest, PC 99001', phone: '555-0119' }
}

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const userId = parseInt(params.id)
  
  // VULNERABLE: IDOR - no authorization check
  const user = users[userId]
  
  if (user) {
    return NextResponse.json({
      success: true,
      user: user,
      warning: 'VULNERABLE: IDOR - can access any user profile by changing ID. Try: /api/users/1, /api/users/2, /api/users/3'
    })
  }
  
  return NextResponse.json({
    error: 'User not found'
  }, { status: 404 })
}

export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const userId = parseInt(params.id)
  const body = await request.json()
  
  // VULNERABLE: IDOR - can modify any user's data
  if (users[userId]) {
    users[userId] = { ...users[userId], ...body }
    
    return NextResponse.json({
      success: true,
      user: users[userId],
      warning: 'VULNERABLE: IDOR - can modify any user without authorization!'
    })
  }
  
  return NextResponse.json({
    error: 'User not found'
  }, { status: 404 })
}

