DROP TABLE IF EXISTS connections;

CREATE TABLE connections (
    id TEXT PRIMARY KEY,
    user1_id TEXT NOT NULL, -- Always the lexicographically smaller user ID
    user2_id TEXT NOT NULL, -- Always the lexicographically larger user ID
    status TEXT NOT NULL DEFAULT 'pending', -- pending, accepted, blocked
    initiated_by TEXT NOT NULL, -- Which user initiated the connection (user1_id or user2_id)
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (initiated_by) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user1_id, user2_id),
    CHECK (user1_id < user2_id), -- Ensure user1_id is always smaller
    CHECK (initiated_by IN (user1_id, user2_id)) -- initiated_by must be one of the users
);

CREATE INDEX IF NOT EXISTS idx_connections_user1_id ON connections(user1_id);
CREATE INDEX IF NOT EXISTS idx_connections_user2_id ON connections(user2_id);
CREATE INDEX IF NOT EXISTS idx_connections_status ON connections(status);
CREATE INDEX IF NOT EXISTS idx_connections_initiated_by ON connections(initiated_by);
