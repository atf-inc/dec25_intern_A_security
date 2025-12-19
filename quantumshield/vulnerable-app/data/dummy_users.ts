/**
 * Dummy Users Data
 * 20 realistic users with complete details for testing
 */

export interface UserData {
  id: number
  username: string
  email: string
  password: string
  role: string
  balance: number
  address: string
  phone: string
  name: string
  created_at: string
}

export const dummyUsers: UserData[] = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@shopvuln.com',
    password: 'admin123',
    role: 'admin',
    balance: 10000.00,
    address: '123 Admin Street, Tech City, TC 12345',
    phone: '555-0100',
    name: 'Admin User',
    created_at: '2024-01-01 10:00:00'
  },
  {
    id: 2,
    username: 'john_doe',
    email: 'john.doe@email.com',
    password: 'password123',
    role: 'user',
    balance: 1250.50,
    address: '456 Oak Avenue, Springfield, SP 54321',
    phone: '555-0101',
    name: 'John Doe',
    created_at: '2024-01-02 11:15:00'
  },
  {
    id: 3,
    username: 'jane_smith',
    email: 'jane.smith@email.com',
    password: 'password123',
    role: 'user',
    balance: 2850.75,
    address: '789 Maple Drive, Riverside, RS 67890',
    phone: '555-0102',
    name: 'Jane Smith',
    created_at: '2024-01-03 09:30:00'
  },
  {
    id: 4,
    username: 'mike_wilson',
    email: 'mike.wilson@email.com',
    password: 'password123',
    role: 'user',
    balance: 750.25,
    address: '321 Pine Street, Mountain View, MV 11223',
    phone: '555-0103',
    name: 'Mike Wilson',
    created_at: '2024-01-04 14:20:00'
  },
  {
    id: 5,
    username: 'sarah_jones',
    email: 'sarah.jones@email.com',
    password: 'password123',
    role: 'user',
    balance: 1950.00,
    address: '654 Elm Road, Lakeside, LS 44556',
    phone: '555-0104',
    name: 'Sarah Jones',
    created_at: '2024-01-05 16:45:00'
  },
  {
    id: 6,
    username: 'david_brown',
    email: 'david.brown@email.com',
    password: 'password123',
    role: 'user',
    balance: 3200.50,
    address: '987 Cedar Lane, Hilltop, HT 77889',
    phone: '555-0105',
    name: 'David Brown',
    created_at: '2024-01-06 08:10:00'
  },
  {
    id: 7,
    username: 'emily_davis',
    email: 'emily.davis@email.com',
    password: 'password123',
    role: 'user',
    balance: 450.00,
    address: '147 Birch Court, Valley View, VV 33445',
    phone: '555-0106',
    name: 'Emily Davis',
    created_at: '2024-01-07 12:30:00'
  },
  {
    id: 8,
    username: 'chris_miller',
    email: 'chris.miller@email.com',
    password: 'password123',
    role: 'user',
    balance: 1650.75,
    address: '258 Willow Way, Greenfield, GF 55667',
    phone: '555-0107',
    name: 'Chris Miller',
    created_at: '2024-01-08 15:20:00'
  },
  {
    id: 9,
    username: 'lisa_anderson',
    email: 'lisa.anderson@email.com',
    password: 'password123',
    role: 'user',
    balance: 2750.25,
    address: '369 Spruce Street, Brookside, BS 66778',
    phone: '555-0108',
    name: 'Lisa Anderson',
    created_at: '2024-01-09 10:50:00'
  },
  {
    id: 10,
    username: 'robert_taylor',
    email: 'robert.taylor@email.com',
    password: 'password123',
    role: 'user',
    balance: 850.50,
    address: '741 Ash Avenue, Parkland, PL 88990',
    phone: '555-0109',
    name: 'Robert Taylor',
    created_at: '2024-01-10 13:15:00'
  },
  {
    id: 11,
    username: 'amanda_white',
    email: 'amanda.white@email.com',
    password: 'password123',
    role: 'user',
    balance: 2100.00,
    address: '852 Cherry Boulevard, Woodside, WS 99001',
    phone: '555-0110',
    name: 'Amanda White',
    created_at: '2024-01-11 11:25:00'
  },
  {
    id: 12,
    username: 'james_martin',
    email: 'james.martin@email.com',
    password: 'password123',
    role: 'user',
    balance: 1450.75,
    address: '963 Poplar Drive, Sunnydale, SD 11223',
    phone: '555-0111',
    name: 'James Martin',
    created_at: '2024-01-12 09:40:00'
  },
  {
    id: 13,
    username: 'jennifer_thomas',
    email: 'jennifer.thomas@email.com',
    password: 'password123',
    role: 'user',
    balance: 3800.25,
    address: '159 Magnolia Road, Fairview, FV 22334',
    phone: '555-0112',
    name: 'Jennifer Thomas',
    created_at: '2024-01-13 14:55:00'
  },
  {
    id: 14,
    username: 'william_jackson',
    email: 'william.jackson@email.com',
    password: 'password123',
    role: 'user',
    balance: 950.00,
    address: '357 Cypress Lane, Clearwater, CW 33445',
    phone: '555-0113',
    name: 'William Jackson',
    created_at: '2024-01-14 16:10:00'
  },
  {
    id: 15,
    username: 'michelle_harris',
    email: 'michelle.harris@email.com',
    password: 'password123',
    role: 'user',
    balance: 2250.50,
    address: '468 Sycamore Street, Milltown, MT 44556',
    phone: '555-0114',
    name: 'Michelle Harris',
    created_at: '2024-01-15 08:30:00'
  },
  {
    id: 16,
    username: 'richard_clark',
    email: 'richard.clark@email.com',
    password: 'password123',
    role: 'user',
    balance: 1750.75,
    address: '579 Hickory Avenue, Riverview, RV 55667',
    phone: '555-0115',
    name: 'Richard Clark',
    created_at: '2024-01-16 12:45:00'
  },
  {
    id: 17,
    username: 'patricia_lewis',
    email: 'patricia.lewis@email.com',
    password: 'password123',
    role: 'user',
    balance: 3100.25,
    address: '680 Walnut Court, Hillcrest, HC 66778',
    phone: '555-0116',
    name: 'Patricia Lewis',
    created_at: '2024-01-17 15:20:00'
  },
  {
    id: 18,
    username: 'daniel_robinson',
    email: 'daniel.robinson@email.com',
    password: 'password123',
    role: 'user',
    balance: 550.00,
    address: '791 Chestnut Way, Meadowbrook, MB 77889',
    phone: '555-0117',
    name: 'Daniel Robinson',
    created_at: '2024-01-18 10:15:00'
  },
  {
    id: 19,
    username: 'linda_walker',
    email: 'linda.walker@email.com',
    password: 'password123',
    role: 'user',
    balance: 2650.50,
    address: '802 Beech Drive, Oakwood, OW 88990',
    phone: '555-0118',
    name: 'Linda Walker',
    created_at: '2024-01-19 13:50:00'
  },
  {
    id: 20,
    username: 'mark_young',
    email: 'mark.young@email.com',
    password: 'password123',
    role: 'user',
    balance: 1350.75,
    address: '913 Fir Boulevard, Pinecrest, PC 99001',
    phone: '555-0119',
    name: 'Mark Young',
    created_at: '2024-01-20 11:35:00'
  }
]

/**
 * Generate SQL INSERT statement for users table
 */
export function generateUserInserts(tableName: string = 'users', includeAllFields: boolean = true): string {
  if (includeAllFields) {
    return dummyUsers.map(user => 
      `(${user.id}, '${user.username}', '${user.email}', '${user.password}', '${user.role}', ${user.balance}, '${user.address}', '${user.phone}', '${user.name}', '${user.created_at}')`
    ).join(',\n    ')
  } else {
    return dummyUsers.map(user => 
      `('${user.username}', '${user.email}', '${user.password}')`
    ).join(',\n    ')
  }
}

/**
 * Generate SQL INSERT for basic users (id, username, email, password)
 */
export function generateBasicUserInserts(): string {
  return dummyUsers.map(user => 
    `('${user.username}', '${user.email}', '${user.password}')`
  ).join(',\n    ')
}

/**
 * Generate SQL INSERT for users with balance
 */
export function generateUserWithBalanceInserts(): string {
  return dummyUsers.map(user => 
    `('${user.username}', ${user.balance})`
  ).join(',\n    ')
}

/**
 * Generate SQL INSERT for full user details
 */
export function generateFullUserInserts(): string {
  return dummyUsers.map(user => 
    `('${user.username}', '${user.email}', '${user.password}', '${user.role}', ${user.balance}, '${user.created_at}')`
  ).join(',\n    ')
}
