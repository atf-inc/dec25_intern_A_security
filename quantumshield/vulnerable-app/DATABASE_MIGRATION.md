# Database Migration Guide

## Overview

The application has been migrated from in-memory SQLite databases (`:memory:`) to persistent file-based databases stored in `data/shopvuln.db`.

## Changes Made

### 1. Database Utility (`lib/database.ts`)
- Created a centralized database utility that manages SQLite connections
- Database file location: `data/shopvuln.db`
- Automatically creates the `data/` directory if it doesn't exist
- Initializes database with schema and dummy users on first run
- Reuses the same database connection across requests

### 2. SQL Injection Route (`app/api/vulnerable/sql-injection/route.ts`)
- Updated to use persistent database via `getDatabase()`
- Properly handles user not found cases (returns 404 with message)
- Supports searching by:
  - Numeric ID: `?id=1`, `?id=2`, etc.
  - Username: `?id=john_doe`, `?id=admin`, etc.
  - Email: `?id=john.doe@email.com`, etc.

### 3. User Not Found Handling
- When a user is not found, the API returns:
  ```json
  {
    "success": false,
    "error": "User not found",
    "message": "No user found with ID/username/email: {search_term}",
    "results": []
  }
  ```
- Status code: `404 Not Found`
- Frontend displays a user-friendly warning message

## Database Schema

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
)
```

## Initialization

On first run, the database is automatically populated with 20 dummy users from `data/dummy_users.ts`:
- admin, john_doe, jane_smith, mike_wilson, sarah_jones
- david_brown, emily_davis, chris_miller, lisa_anderson, robert_taylor
- amanda_white, james_martin, jennifer_thomas, william_jackson, michelle_harris
- richard_clark, patricia_lewis, daniel_robinson, linda_walker, mark_young

## Testing

### Valid Searches
- `GET /api/vulnerable/sql-injection?id=1` - Find user by ID
- `GET /api/vulnerable/sql-injection?id=john_doe` - Find user by username
- `GET /api/vulnerable/sql-injection?id=john.doe@email.com` - Find user by email

### Invalid Searches (User Not Found)
- `GET /api/vulnerable/sql-injection?id=999` - Non-existent ID
- `GET /api/vulnerable/sql-injection?id=invalid_user` - Non-existent username
- `GET /api/vulnerable/sql-injection?id=invalid@email.com` - Non-existent email

### SQL Injection Tests (Still Vulnerable)
- `GET /api/vulnerable/sql-injection?id=1 OR 1=1` - Get all users
- `GET /api/vulnerable/sql-injection?id=john_doe' OR '1'='1` - Username injection

## File Location

- Database file: `data/shopvuln.db`
- Database utility: `lib/database.ts`
- Dummy users data: `data/dummy_users.ts`

## Notes

- The database file is automatically created on first API call
- The `.gitignore` file already excludes `*.db` files
- Database persists across server restarts
- All 20 dummy users are pre-populated in the database
