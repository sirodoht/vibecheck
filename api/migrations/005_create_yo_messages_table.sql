CREATE TABLE yo_messages (
    id TEXT PRIMARY KEY,
    from_user_id TEXT NOT NULL,
    to_user_id TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (from_user_id) REFERENCES users(id),
    FOREIGN KEY (to_user_id) REFERENCES users(id)
);

CREATE INDEX idx_yo_messages_from_user ON yo_messages(from_user_id, sent_at DESC);
CREATE INDEX idx_yo_messages_to_user ON yo_messages(to_user_id, sent_at DESC);
