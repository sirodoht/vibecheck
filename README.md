# Vibecheck API

## Setup

```bash
cargo build
cargo run -- --serve
```

The server will start at `http://127.0.0.1:3000`

### Database

The application automatically creates and manages a SQLite database (`vibecheckapi.db`) with migrations.

## API Endpoints

### 🏠 Web Interface

#### Get Index Page
```bash
curl http://127.0.0.1:3000/
```
**Response:** HTML page displaying all registered users

---

### 👤 User Management

#### Register User
```bash
curl -X POST http://127.0.0.1:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "password": "securepass123"}'
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "user_id": "a1b2c3d4-5678-90ab-cdef-1234567890ab"
}
```

**Error Response (409):**
```json
{
  "error": "Username already exists"
}
```

#### Login User
```bash
curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "password": "securepass123"}'
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
    "username": "newuser",
    "created_at": "2025-09-20T13:30:21.546077+00:00"
  },
  "token": "f398c73c-f028-4f48-b7d7-246c8572d000"
}
```

**Error Response (401):**
```json
{
  "error": "Invalid username or password"
}
```

---

### 🤝 Connections (Authenticated Endpoints)

> **Note:** All connection endpoints require authentication via `Authorization: Bearer <token>` header.

#### Add Connection
```bash
curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN_HERE" \
  -d '{"username": "friendusername"}'
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Successfully connected to friendusername",
  "connection_id": "d5dd5e56-30b5-494c-a0c6-56cf16d0a7ae"
}
```

**Error Responses:**
```json
{"error": "User not found"}                    // 404
{"error": "Connection already exists"}         // 409
{"error": "Cannot connect to yourself"}       // 409
{"error": "Missing Authorization header"}     // 401
{"error": "Invalid session token"}            // 401
```

#### Get User Connections
```bash
curl -X GET http://127.0.0.1:3000/api/connections \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN_HERE"
```

**Success Response (200):**
```json
{
  "success": true,
  "connections": [
    {
      "id": "d5dd5e56-30b5-494c-a0c6-56cf16d0a7ae",
      "user_id": "7de689bd-f409-4636-8d0b-b64b69c798fe",
      "friend_id": "cda046dd-666f-4219-8369-2c6051317e64",
      "friend_username": "friendusername",
      "status": "accepted",
      "created_at": "2025-09-20T13:38:01.065593+00:00"
    }
  ]
}
```

## Complete Usage Example

```bash
# 1. Register two users
curl -X POST http://127.0.0.1:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}'

curl -X POST http://127.0.0.1:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "password": "password456"}'

# 2. Login as Alice and store token
TOKEN=$(curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}' -s | jq -r '.token')

# 3. Alice connects to Bob
curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"username": "bob"}'

# 4. Alice checks her connections
curl -X GET http://127.0.0.1:3000/api/connections \
  -H "Authorization: Bearer $TOKEN"

# 5. View all users on web interface
curl http://127.0.0.1:3000/
```

## Authentication

### Session Tokens
- **Format:** UUID v4 strings
- **Location:** `Authorization: Bearer <token>` header
- **Lifetime:** **Permanent** (never expire)
- **Storage:** Stored in database `sessions` table
- **Multiple Sessions:** Users can have multiple active tokens

### Protected Endpoints
- `POST /api/connections` - Add friend/connection
- `GET /api/connections` - Get user's connections

### Public Endpoints
- `GET /` - Web interface
- `POST /api/register` - User registration
- `POST /api/login` - User authentication

## HTTP Status Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Successful requests |
| 400 | Bad Request | Invalid input data |
| 401 | Unauthorized | Missing/invalid auth token |
| 404 | Not Found | User/resource doesn't exist |
| 409 | Conflict | Duplicate/conflicting resource |
| 500 | Internal Server Error | Server-side errors |

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,              -- UUID
    username TEXT NOT NULL UNIQUE,    -- User's chosen username
    password_hash TEXT NOT NULL,      -- Argon2 hashed password
    created_at TEXT NOT NULL,         -- ISO 8601 timestamp
    updated_at TEXT NOT NULL          -- ISO 8601 timestamp
);
```

### Sessions Table
```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,              -- UUID
    user_id TEXT NOT NULL,            -- Foreign key to users.id
    token TEXT NOT NULL UNIQUE,       -- Session token (UUID)
    created_at TEXT NOT NULL,         -- ISO 8601 timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Connections Table
```sql
CREATE TABLE connections (
    id TEXT PRIMARY KEY,              -- UUID
    user_id TEXT NOT NULL,            -- Foreign key to users.id
    friend_id TEXT NOT NULL,          -- Foreign key to users.id
    status TEXT NOT NULL DEFAULT 'pending', -- Status: pending, accepted, blocked
    created_at TEXT NOT NULL,         -- ISO 8601 timestamp
    updated_at TEXT NOT NULL,         -- ISO 8601 timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, friend_id)
);
```

## Development

### Running the Server
```bash
# Development mode with auto-reload
cargo watch -x 'run -- --serve'

# Production mode
cargo run --release -- --serve
```

### Database Management
```bash
# View database contents
sqlite3 vibecheckapi.db

# Check users
sqlite3 vibecheckapi.db "SELECT username, created_at FROM users;"

# Check sessions
sqlite3 vibecheckapi.db "SELECT token, created_at FROM sessions;"

# Check connections
sqlite3 vibecheckapi.db "SELECT u1.username as user, u2.username as friend, c.status FROM connections c JOIN users u1 ON c.user_id = u1.id JOIN users u2 ON c.friend_id = u2.id;"
```

### Code Structure
```
src/
├── main.rs          # API routes, handlers, and models
└── database.rs      # Database connection and operations

migrations/
├── 001_create_users_table.sql
├── 002_create_sessions_table.sql
└── 003_create_connections_table.sql

templates/
├── layout.html      # Base HTML template
└── index.html       # User listing page
```
