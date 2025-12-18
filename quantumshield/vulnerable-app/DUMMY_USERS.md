# Dummy Users Database

This document lists all 20 dummy users that have been added to the database for testing purposes.

## User List

| ID | Username | Email | Password | Role | Balance | Phone | Address |
|----|----------|-------|----------|------|---------|-------|---------|
| 1 | admin | admin@shopvuln.com | admin123 | admin | $10,000.00 | 555-0100 | 123 Admin Street, Tech City, TC 12345 |
| 2 | john_doe | john.doe@email.com | password123 | user | $1,250.50 | 555-0101 | 456 Oak Avenue, Springfield, SP 54321 |
| 3 | jane_smith | jane.smith@email.com | password123 | user | $2,850.75 | 555-0102 | 789 Maple Drive, Riverside, RS 67890 |
| 4 | mike_wilson | mike.wilson@email.com | password123 | user | $750.25 | 555-0103 | 321 Pine Street, Mountain View, MV 11223 |
| 5 | sarah_jones | sarah.jones@email.com | password123 | user | $1,950.00 | 555-0104 | 654 Elm Road, Lakeside, LS 44556 |
| 6 | david_brown | david.brown@email.com | password123 | user | $3,200.50 | 555-0105 | 987 Cedar Lane, Hilltop, HT 77889 |
| 7 | emily_davis | emily.davis@email.com | password123 | user | $450.00 | 555-0106 | 147 Birch Court, Valley View, VV 33445 |
| 8 | chris_miller | chris.miller@email.com | password123 | user | $1,650.75 | 555-0107 | 258 Willow Way, Greenfield, GF 55667 |
| 9 | lisa_anderson | lisa.anderson@email.com | password123 | user | $2,750.25 | 555-0108 | 369 Spruce Street, Brookside, BS 66778 |
| 10 | robert_taylor | robert.taylor@email.com | password123 | user | $850.50 | 555-0109 | 741 Ash Avenue, Parkland, PL 88990 |
| 11 | amanda_white | amanda.white@email.com | password123 | user | $2,100.00 | 555-0110 | 852 Cherry Boulevard, Woodside, WS 99001 |
| 12 | james_martin | james.martin@email.com | password123 | user | $1,450.75 | 555-0111 | 963 Poplar Drive, Sunnydale, SD 11223 |
| 13 | jennifer_thomas | jennifer.thomas@email.com | password123 | user | $3,800.25 | 555-0112 | 159 Magnolia Road, Fairview, FV 22334 |
| 14 | william_jackson | william.jackson@email.com | password123 | user | $950.00 | 555-0113 | 357 Cypress Lane, Clearwater, CW 33445 |
| 15 | michelle_harris | michelle.harris@email.com | password123 | user | $2,250.50 | 555-0114 | 468 Sycamore Street, Milltown, MT 44556 |
| 16 | richard_clark | richard.clark@email.com | password123 | user | $1,750.75 | 555-0115 | 579 Hickory Avenue, Riverview, RV 55667 |
| 17 | patricia_lewis | patricia.lewis@email.com | password123 | user | $3,100.25 | 555-0116 | 680 Walnut Court, Hillcrest, HC 66778 |
| 18 | daniel_robinson | daniel.robinson@email.com | password123 | user | $550.00 | 555-0117 | 791 Chestnut Way, Meadowbrook, MB 77889 |
| 19 | linda_walker | linda.walker@email.com | password123 | user | $2,650.50 | 555-0118 | 802 Beech Drive, Oakwood, OW 88990 |
| 20 | mark_young | mark.young@email.com | password123 | user | $1,350.75 | 555-0119 | 913 Fir Boulevard, Pinecrest, PC 99001 |

## Testing

You can test accessing these users via:

### SQL Injection
- GET `/api/vulnerable/sql-injection?id=1` - Get user 1
- GET `/api/vulnerable/sql-injection?id=1 OR 1=1` - Get all users
- POST `/api/vulnerable/sql-injection` with `{"username": "john_doe", "password": "password123"}`

### IDOR
- GET `/api/users/1` through `/api/users/20` - Access any user
- GET `/api/vulnerable/idor?id=1` through `id=20`

### Authentication
- POST `/api/auth/login` with any username/password from the list above

### Admin Users
- GET `/api/admin/users` - View all users (requires admin role)

### CSRF Transfer
- POST `/api/csrf/transfer` with `{"toUserId": 2, "amount": 100}` - Transfer between users

## Default Credentials

All users (except admin) use the password: `password123`
Admin uses: `admin123`

## Notes

- All users have realistic email addresses
- All users have unique phone numbers
- All users have complete addresses
- Balance amounts vary from $450 to $10,000
- All users have creation timestamps
- User IDs range from 1 to 20
