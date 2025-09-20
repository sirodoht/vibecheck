use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use sqlx::{Pool, Row, Sqlite, SqlitePool, migrate::MigrateDatabase};
use std::{fs, path::Path};

pub struct Database {
    pub pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        // Create database if it doesn't exist
        if !Sqlite::database_exists(database_url).await.unwrap_or(false) {
            println!("Creating database {}", database_url);
            match Sqlite::create_database(database_url).await {
                Ok(_) => println!("Successfully created database"),
                Err(error) => panic!("Error creating database: {}", error),
            }
        } else {
            println!("Database already exists");
        }

        // Connect to database
        let pool = SqlitePool::connect(database_url).await?;

        // Disable WAL mode to avoid -shm and -wal files
        sqlx::query("PRAGMA journal_mode = DELETE")
            .execute(&pool)
            .await?;

        Ok(Database { pool })
    }

    pub async fn run_migrations(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running database migrations...");

        // Create migrations table if it doesn't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS _migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL UNIQUE,
                executed_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Get all migration files
        let migrations_dir = Path::new("migrations");
        if !migrations_dir.exists() {
            println!("Migrations directory not found");
            return Ok(());
        }

        let mut entries: Vec<_> = fs::read_dir(migrations_dir)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "sql")
                    .unwrap_or(false)
            })
            .collect();

        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            let filename = entry.file_name().to_string_lossy().to_string();

            // Check if migration has already been executed
            let executed = sqlx::query("SELECT filename FROM _migrations WHERE filename = ?")
                .bind(&filename)
                .fetch_optional(&self.pool)
                .await?
                .is_some();

            if executed {
                println!("Migration {} already executed, skipping", filename);
                continue;
            }

            println!("Executing migration: {}", filename);

            // Read and execute migration file
            let migration_sql = fs::read_to_string(entry.path())?;

            // Execute the migration in a transaction
            let mut tx = self.pool.begin().await?;

            // Split by semicolons and execute each statement
            for statement in migration_sql.split(';') {
                let statement = statement.trim();
                if !statement.is_empty() {
                    sqlx::query(statement).execute(&mut *tx).await?;
                }
            }

            // Record the migration as executed
            sqlx::query(
                "INSERT INTO _migrations (filename, executed_at) VALUES (?, datetime('now'))",
            )
            .bind(&filename)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;

            println!("Successfully executed migration: {}", filename);
        }

        println!("All migrations completed");
        Ok(())
    }

    // User-related database methods
    pub async fn get_all_users(&self) -> Result<Vec<crate::User>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, username, password_hash, created_at FROM users ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        let users = rows
            .into_iter()
            .map(|row| crate::User {
                id: row.get("id"),
                username: row.get("username"),
                password_hash: row.get("password_hash"),
                created_at: row.get("created_at"),
            })
            .collect();

        Ok(users)
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Check if username already exists
        let existing_user = sqlx::query("SELECT id FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;

        if existing_user.is_some() {
            return Err("Username already exists".into());
        }

        // Hash the password
        let password_hash = self.hash_password(password)?;

        // Generate new user ID
        let user_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        // Insert user into database
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(&user_id)
        .bind(username)
        .bind(&password_hash)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(user_id)
    }

    pub async fn verify_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<crate::User>, Box<dyn std::error::Error>> {
        let user_row = sqlx::query(
            "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = user_row {
            let stored_hash: String = row.get("password_hash");

            if self.verify_password(password, &stored_hash)? {
                let user = crate::User {
                    id: row.get("id"),
                    username: row.get("username"),
                    password_hash: stored_hash,
                    created_at: row.get("created_at"),
                };
                Ok(Some(user))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    fn hash_password(&self, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("Password hashing failed: {}", e))?
            .to_string();
        Ok(password_hash)
    }

    fn verify_password(
        &self,
        password: &str,
        hash: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let argon2 = Argon2::default();
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| format!("Invalid password hash: {}", e))?;

        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    // Session management methods
    pub async fn create_session(
        &self,
        user_id: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Generate a simple session token (UUID)
        let token = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let session_id = uuid::Uuid::new_v4().to_string();

        // Insert session into database (no expiration)
        sqlx::query("INSERT INTO sessions (id, user_id, token, created_at) VALUES (?, ?, ?, ?)")
            .bind(&session_id)
            .bind(user_id)
            .bind(&token)
            .bind(&now)
            .execute(&self.pool)
            .await?;

        Ok(token)
    }

    pub async fn validate_session(
        &self,
        token: &str,
    ) -> Result<Option<crate::User>, Box<dyn std::error::Error>> {
        let session_row = sqlx::query(
            "SELECT s.user_id, u.username, u.password_hash, u.created_at
             FROM sessions s
             JOIN users u ON s.user_id = u.id
             WHERE s.token = ?",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = session_row {
            let user = crate::User {
                id: row.get("user_id"),
                username: row.get("username"),
                password_hash: row.get("password_hash"),
                created_at: row.get("created_at"),
            };
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    // Connection management methods
    pub async fn create_connection(
        &self,
        user_id: &str,
        friend_username: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Find the friend by username
        let friend_row = sqlx::query("SELECT id FROM users WHERE username = ?")
            .bind(friend_username)
            .fetch_optional(&self.pool)
            .await?;

        let friend_id = match friend_row {
            Some(row) => row.get::<String, _>("id"),
            None => return Err("User not found".into()),
        };

        // Check if user is trying to connect to themselves
        if user_id == friend_id {
            return Err("Cannot connect to yourself".into());
        }

        // Determine user1_id and user2_id (user1 should be lexicographically smaller)
        let (user1_id, user2_id) = if user_id < friend_id.as_str() {
            (user_id, friend_id.as_str())
        } else {
            (friend_id.as_str(), user_id)
        };

        // Check if connection already exists
        let existing_connection =
            sqlx::query("SELECT id FROM connections WHERE user1_id = ? AND user2_id = ?")
                .bind(user1_id)
                .bind(user2_id)
                .fetch_optional(&self.pool)
                .await?;

        if existing_connection.is_some() {
            return Err("Connection already exists".into());
        }

        // Create new connection with pending status
        let connection_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO connections (id, user1_id, user2_id, status, initiated_by, created_at, updated_at) VALUES (?, ?, ?, 'pending', ?, ?, ?)"
        )
        .bind(&connection_id)
        .bind(user1_id)
        .bind(user2_id)
        .bind(user_id) // The user who initiated the connection
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(connection_id)
    }

    pub async fn get_user_connections(
        &self,
        user_id: &str,
    ) -> Result<Vec<crate::Connection>, Box<dyn std::error::Error>> {
        // Get connections where user is either user1 or user2
        let rows = sqlx::query(
            "SELECT c.id, c.user1_id, c.user2_id, c.status, c.initiated_by, c.created_at,
                    CASE 
                        WHEN c.user1_id = ? THEN u2.username 
                        ELSE u1.username 
                    END as other_username
             FROM connections c
             JOIN users u1 ON c.user1_id = u1.id
             JOIN users u2 ON c.user2_id = u2.id
             WHERE (c.user1_id = ? OR c.user2_id = ?)
             ORDER BY c.created_at DESC",
        )
        .bind(user_id)
        .bind(user_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let connections = rows
            .into_iter()
            .map(|row| crate::Connection {
                id: row.get("id"),
                user1_id: row.get("user1_id"),
                user2_id: row.get("user2_id"),
                other_username: row.get("other_username"),
                status: row.get("status"),
                initiated_by: row.get("initiated_by"),
                created_at: row.get("created_at"),
            })
            .collect();

        Ok(connections)
    }

    pub async fn get_users_with_friends(
        &self,
    ) -> Result<Vec<crate::UserWithFriends>, Box<dyn std::error::Error>> {
        // Get all accepted connections and create bidirectional friendships
        let rows = sqlx::query(
            "SELECT c.id, c.user1_id, c.user2_id, c.created_at,
                    u1.username as user1_username, u2.username as user2_username
             FROM connections c
             JOIN users u1 ON c.user1_id = u1.id
             JOIN users u2 ON c.user2_id = u2.id
             WHERE c.status = 'accepted'
             ORDER BY c.created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        // Group connections by user (bidirectional)
        let mut users_map: std::collections::HashMap<String, Vec<crate::Friend>> =
            std::collections::HashMap::new();

        for row in rows {
            let connection_id: String = row.get("id");
            let user1_username: String = row.get("user1_username");
            let user2_username: String = row.get("user2_username");
            let created_at: String = row.get("created_at");

            // Add user2 as friend of user1
            let friend1 = crate::Friend {
                username: user2_username.clone(),
                connection_id: connection_id.clone(),
                created_at: created_at.clone(),
            };
            users_map
                .entry(user1_username.clone())
                .or_default()
                .push(friend1);

            // Add user1 as friend of user2
            let friend2 = crate::Friend {
                username: user1_username,
                connection_id,
                created_at,
            };
            users_map.entry(user2_username).or_default().push(friend2);
        }

        // Convert to Vec<UserWithFriends>
        let mut users_with_friends: Vec<crate::UserWithFriends> = users_map
            .into_iter()
            .map(|(username, friends)| crate::UserWithFriends { username, friends })
            .collect();

        // Sort by username for consistent display
        users_with_friends.sort_by(|a, b| a.username.cmp(&b.username));

        Ok(users_with_friends)
    }

    pub async fn accept_connection(
        &self,
        connection_id: &str,
        user_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // First, verify that the connection exists and the user is authorized to accept it
        let connection_row = sqlx::query(
            "SELECT user1_id, user2_id, initiated_by, status FROM connections WHERE id = ?",
        )
        .bind(connection_id)
        .fetch_optional(&self.pool)
        .await?;

        let (user1_id, user2_id, initiated_by, status) = match connection_row {
            Some(row) => (
                row.get::<String, _>("user1_id"),
                row.get::<String, _>("user2_id"),
                row.get::<String, _>("initiated_by"),
                row.get::<String, _>("status"),
            ),
            None => return Err("Connection not found".into()),
        };

        // Check if connection is already accepted
        if status == "accepted" {
            return Err("Connection is already accepted".into());
        }

        // Check if the user is part of this connection
        if user_id != user1_id && user_id != user2_id {
            return Err("You are not authorized to accept this connection".into());
        }

        // Check if the user is trying to accept their own request
        if user_id == initiated_by {
            return Err("You cannot accept your own connection request".into());
        }

        // Update the connection status to accepted
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE connections SET status = 'accepted', updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(connection_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
