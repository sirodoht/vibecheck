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

#### Get Friends Page
```bash
curl http://127.0.0.1:3000/friends
```
**Response:** HTML page showing all users and their accepted friendships

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

#### Send Connection Request
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
  "message": "Connection request sent to friendusername. Waiting for acceptance.",
  "connection_id": "d5dd5e56-30b5-494c-a0c6-56cf16d0a7ae"
}
```

**Error Responses:**
```json
{"error": "User not found"}                   # 404
{"error": "Connection already exists"}        # 409
{"error": "Cannot connect to yourself"}       # 409
{"error": "Missing Authorization header"}     # 401
{"error": "Invalid session token"}            # 401
```

#### Accept Connection Request
```bash
curl -X POST http://127.0.0.1:3000/api/connections/accept \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN_HERE" \
  -d '{"connection_id": "d5dd5e56-30b5-494c-a0c6-56cf16d0a7ae"}'
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Connection accepted successfully"
}
```

**Error Responses:**
```json
{"error": "Connection not found"}                        # 404
{"error": "Connection is already accepted"}              # 409
{"error": "You are not authorized to accept this connection"} # 403
{"error": "You cannot accept your own connection request"}    # 403
{"error": "Missing Authorization header"}                # 401
{"error": "Invalid session token"}                       # 401
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
      "user1_id": "7de689bd-f409-4636-8d0b-b64b69c798fe",
      "user2_id": "cda046dd-666f-4219-8369-2c6051317e64",
      "other_username": "friendusername",
      "status": "accepted",
      "initiated_by": "cda046dd-666f-4219-8369-2c6051317e64",
      "created_at": "2025-09-20T13:38:01.065593+00:00"
    },
    {
      "id": "a1b2c3d4-1234-5678-90ab-cdef12345678",
      "user1_id": "7de689bd-f409-4636-8d0b-b64b69c798fe",
      "user2_id": "e4f5a6b7-8901-2345-6789-abcdef123456",
      "other_username": "anotherusername",
      "status": "pending",
      "initiated_by": "7de689bd-f409-4636-8d0b-b64b69c798fe",
      "created_at": "2025-09-20T14:15:30.123456+00:00"
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
ALICE_TOKEN=$(curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}' -s | jq -r '.token')

# 3. Login as Bob and store token
BOB_TOKEN=$(curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "password": "password456"}' -s | jq -r '.token')

# 4. Alice sends connection request to Bob
CONNECTION_RESPONSE=$(curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d '{"username": "bob"}' -s)

# Extract connection ID from response
CONNECTION_ID=$(echo $CONNECTION_RESPONSE | jq -r '.connection_id')

# 5. Bob checks his connections (will see pending request)
curl -X GET http://127.0.0.1:3000/api/connections \
  -H "Authorization: Bearer $BOB_TOKEN"

# 6. Bob accepts Alice's connection request
curl -X POST http://127.0.0.1:3000/api/connections/accept \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -d "{\"connection_id\": \"$CONNECTION_ID\"}"

# 7. Alice checks her connections (now shows accepted)
curl -X GET http://127.0.0.1:3000/api/connections \
  -H "Authorization: Bearer $ALICE_TOKEN"

# 8. View all users and friendships on web interface
curl http://127.0.0.1:3000/
curl http://127.0.0.1:3000/friends
```

## Test Scenarios

### Scenario 1: Basic Connection Flow

```bash
# 1. Create Alice
curl -X POST http://127.0.0.1:3000/api/register -H "Content-Type: application/json" -d '{"username": "alice", "password": "password123"}'

# 2. Create Bob  
curl -X POST http://127.0.0.1:3000/api/register -H "Content-Type: application/json" -d '{"username": "bob", "password": "password456"}'

# 3. Alice logs in and gets token
ALICE_TOKEN=$(curl -X POST http://127.0.0.1:3000/api/login -H "Content-Type: application/json" -d '{"username": "alice", "password": "password123"}' -s | jq -r '.token')

echo "Alice's token: $ALICE_TOKEN"

# 4. Bob logs in and gets token
BOB_TOKEN=$(curl -X POST http://127.0.0.1:3000/api/login -H "Content-Type: application/json" -d '{"username": "bob", "password": "password456"}' -s | jq -r '.token')

echo "Bob's token: $BOB_TOKEN"

# 5. Alice sends connection request to Bob
CONNECTION_RESPONSE=$(curl -X POST http://127.0.0.1:3000/api/connections -H "Content-Type: application/json" -H "Authorization: Bearer $ALICE_TOKEN" -d '{"username": "bob"}' -s)

echo "Connection request response: $CONNECTION_RESPONSE"

# Extract connection ID
CONNECTION_ID=$(echo $CONNECTION_RESPONSE | jq -r '.connection_id')
echo "Connection ID: $CONNECTION_ID"

# 6. Bob views his connections (should see pending request from Alice)
echo "Bob's connections (should show pending):"
curl -X GET http://127.0.0.1:3000/api/connections -H "Authorization: Bearer $BOB_TOKEN" -s | jq '.'

# 7. Bob accepts Alice's connection request
echo "Bob accepts connection:"
curl -X POST http://127.0.0.1:3000/api/connections/accept -H "Content-Type: application/json" -H "Authorization: Bearer $BOB_TOKEN" -d "{\"connection_id\": \"$CONNECTION_ID\"}" -s | jq '.'

# 8. Alice views her connections (should show accepted)
echo "Alice's connections (should show accepted):"
curl -X GET http://127.0.0.1:3000/api/connections -H "Authorization: Bearer $ALICE_TOKEN" -s | jq '.'

# 9. Bob views his connections (should also show accepted)
echo "Bob's connections (should show accepted):"
curl -X GET http://127.0.0.1:3000/api/connections -H "Authorization: Bearer $BOB_TOKEN" -s | jq '.'
```

### Scenario 2: Multiple Users Network

```bash
# Create a network of users and test bidirectional friendships

# 1. Create multiple users
curl -X POST http://127.0.0.1:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "charlie", "password": "password789"}'

curl -X POST http://127.0.0.1:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "diana", "password": "passwordabc"}'

# 2. Get tokens for all users
CHARLIE_TOKEN=$(curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "charlie", "password": "password789"}' -s | jq -r '.token')

DIANA_TOKEN=$(curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "diana", "password": "passwordabc"}' -s | jq -r '.token')

# 3. Charlie sends requests to Alice and Bob
CONN1_RESPONSE=$(curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CHARLIE_TOKEN" \
  -d '{"username": "alice"}' -s)

CONN2_RESPONSE=$(curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CHARLIE_TOKEN" \
  -d '{"username": "bob"}' -s)

# 4. Diana sends request to Alice
CONN3_RESPONSE=$(curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DIANA_TOKEN" \
  -d '{"username": "alice"}' -s)

# Extract connection IDs
CONN1_ID=$(echo $CONN1_RESPONSE | jq -r '.connection_id')
CONN2_ID=$(echo $CONN2_RESPONSE | jq -r '.connection_id')  
CONN3_ID=$(echo $CONN3_RESPONSE | jq -r '.connection_id')

# 5. Alice accepts all pending requests
curl -X POST http://127.0.0.1:3000/api/connections/accept \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d "{\"connection_id\": \"$CONN1_ID\"}" -s

curl -X POST http://127.0.0.1:3000/api/connections/accept \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d "{\"connection_id\": \"$CONN3_ID\"}" -s

# 6. Bob accepts Charlie's request
curl -X POST http://127.0.0.1:3000/api/connections/accept \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -d "{\"connection_id\": \"$CONN2_ID\"}" -s

# 7. Check final network state
echo "=== Final Network State ==="
echo "Alice's friends:"
curl -X GET http://127.0.0.1:3000/api/connections \
  -H "Authorization: Bearer $ALICE_TOKEN" -s | jq '.connections[] | {other_username, status}'

echo "Bob's friends:"  
curl -X GET http://127.0.0.1:3000/api/connections \
  -H "Authorization: Bearer $BOB_TOKEN" -s | jq '.connections[] | {other_username, status}'

echo "Charlie's friends:"
curl -X GET http://127.0.0.1:3000/api/connections \
  -H "Authorization: Bearer $CHARLIE_TOKEN" -s | jq '.connections[] | {other_username, status}'

echo "Diana's friends:"
curl -X GET http://127.0.0.1:3000/api/connections \
  -H "Authorization: Bearer $DIANA_TOKEN" -s | jq '.connections[] | {other_username, status}'
```

### Scenario 3: Error Testing

```bash
# Test various error conditions

# 1. Try to connect to non-existent user
echo "Testing connection to non-existent user:"
curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d '{"username": "nonexistent"}' -s | jq '.'

# 2. Try to connect to yourself
echo "Testing self-connection:"
curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d '{"username": "alice"}' -s | jq '.'

# 3. Try to send duplicate connection request
echo "Testing duplicate connection:"
curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d '{"username": "bob"}' -s | jq '.'

# 4. Try to accept non-existent connection
echo "Testing non-existent connection acceptance:"
curl -X POST http://127.0.0.1:3000/api/connections/accept \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d '{"connection_id": "fake-id"}' -s | jq '.'

# 5. Try to accept your own request
SELF_CONN_RESPONSE=$(curl -X POST http://127.0.0.1:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "eve", "password": "password999"}' -s)

EVE_TOKEN=$(curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "eve", "password": "password999"}' -s | jq -r '.token')

EVE_CONN_RESPONSE=$(curl -X POST http://127.0.0.1:3000/api/connections \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $EVE_TOKEN" \
  -d '{"username": "alice"}' -s)

EVE_CONN_ID=$(echo $EVE_CONN_RESPONSE | jq -r '.connection_id')

echo "Testing self-acceptance:"
curl -X POST http://127.0.0.1:3000/api/connections/accept \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $EVE_TOKEN" \
  -d "{\"connection_id\": \"$EVE_CONN_ID\"}" -s | jq '.'
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
sqlite3 vibecheckapi.db "SELECT u1.username as user1, u2.username as user2, c.status, u3.username as initiated_by FROM connections c JOIN users u1 ON c.user1_id = u1.id JOIN users u2 ON c.user2_id = u2.id JOIN users u3 ON c.initiated_by = u3.id;"
```

### Code Structure
```
src/
├── main.rs          # API routes, handlers, and models
└── database.rs      # Database connection and operations

migrations/
├── 001_create_users_table.sql
├── 002_create_sessions_table.sql
├── 003_create_connections_table.sql
└── 004_update_connections_bidirectional.sql

templates/
├── layout.html      # Base HTML template
├── index.html       # User listing page
└── friends.html     # Friendships listing page
```
