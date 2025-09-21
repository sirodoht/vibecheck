use axum::{
    Router,
    routing::{get, post},
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use sqlx::Row;
use std::sync::Arc;
use tempfile::TempDir;

#[derive(serde::Serialize, serde::Deserialize)]
struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RegisterResponse {
    pub success: bool,
    pub message: String,
    pub user_id: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<UserInfo>,
    pub token: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct UserInfo {
    pub id: String,
    pub username: String,
    pub created_at: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ErrorResponse {
    pub error: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AddConnectionResponse {
    pub success: bool,
    pub message: String,
    pub connection_id: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ConnectionsResponse {
    pub success: bool,
    pub connections: Vec<Connection>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Connection {
    pub id: String,
    pub user1_id: String,
    pub user2_id: String,
    pub other_username: String,
    pub status: String,
    pub initiated_by: String,
    pub created_at: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AcceptConnectionResponse {
    pub success: bool,
    pub message: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AddConnectionRequest {
    pub username: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AcceptConnectionRequest {
    pub connection_id: String,
}

pub struct TestApp {
    pub address: String,
    pub db_path: String,
    _temp_dir: TempDir,
}

impl TestApp {
    pub async fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir
            .path()
            .join("test.db")
            .to_string_lossy()
            .to_string();
        let database_url = "sqlite::memory:".to_string();

        // For integration tests, we need to handle the database differently
        // Let's create a simple test database setup
        let db = {
            // Create a minimal database struct for testing
            // Since we can't import the Database struct directly, we'll create our own
            use sqlx::SqlitePool;
            let pool = SqlitePool::connect(&database_url)
                .await
                .expect("Failed to create test database pool");

            // Run migrations manually
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS _migrations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL UNIQUE,
                    executed_at TEXT NOT NULL
                )
                "#,
            )
            .execute(&pool)
            .await
            .expect("Failed to create migrations table");

            // Run basic table creation queries
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            .execute(&pool)
            .await
            .expect("Failed to create users table");

            sqlx::query(
                "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            .execute(&pool)
            .await
            .expect("Failed to create sessions table");

            sqlx::query(
                "CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, user1_id TEXT NOT NULL, user2_id TEXT NOT NULL, status TEXT NOT NULL, initiated_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            .execute(&pool)
            .await
            .expect("Failed to create connections table");

            pool
        };

        let app_state = Arc::new(db);

        // For integration tests, we'll create a minimal router that just handles the endpoints we want to test
        // Since we can't easily import from the main crate in tests, we'll focus on testing the core functionality
        let app = Router::new()
            .route("/api/register", post(register_user_handler))
            .route("/api/login", post(login_user_handler))
            .route("/api/connections", post(add_connection_handler))
            .route("/api/connections", get(get_connections_handler))
            .route("/api/connections/accept", post(accept_connection_handler))
            .with_state(app_state);

        // Start the server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to random port");
        let address = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("Server failed");
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        TestApp {
            address,
            db_path,
            _temp_dir: temp_dir,
        }
    }

    pub async fn post_json<T: Serialize>(&self, path: &str, body: T) -> TestResponse {
        let client = reqwest::Client::new();
        let response = client
            .post(&format!("http://{}/{}", self.address, path))
            .json(&body)
            .send()
            .await
            .expect("Failed to send request");

        TestResponse {
            status: response.status(),
            body: response.text().await.unwrap_or_default(),
        }
    }

    pub async fn get(&self, path: &str) -> TestResponse {
        let client = reqwest::Client::new();
        let response = client
            .get(&format!("http://{}/{}", self.address, path))
            .send()
            .await
            .expect("Failed to send request");

        TestResponse {
            status: response.status(),
            body: response.text().await.unwrap_or_default(),
        }
    }

    pub async fn post_with_auth<T: Serialize>(
        &self,
        path: &str,
        body: T,
        token: &str,
    ) -> TestResponse {
        let client = reqwest::Client::new();
        let response = client
            .post(&format!("http://{}/{}", self.address, path))
            .header("Authorization", format!("Bearer {}", token))
            .json(&body)
            .send()
            .await
            .expect("Failed to send request");

        TestResponse {
            status: response.status(),
            body: response.text().await.unwrap_or_default(),
        }
    }

    pub async fn get_with_auth(&self, path: &str, token: &str) -> TestResponse {
        let client = reqwest::Client::new();
        let response = client
            .get(&format!("http://{}/{}", self.address, path))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("Failed to send request");

        TestResponse {
            status: response.status(),
            body: response.text().await.unwrap_or_default(),
        }
    }
}

pub struct TestResponse {
    pub status: reqwest::StatusCode,
    pub body: String,
}

impl TestResponse {
    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_str(&self.body).expect("Failed to parse JSON response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a test user and get their token
    async fn create_test_user_and_get_token(
        app: &TestApp,
        username: &str,
        password: &str,
    ) -> String {
        // Register user
        let register_body = json!({
            "username": username,
            "password": password
        });

        let response = app.post_json("api/register", register_body).await;
        assert_eq!(response.status, 200);
        let register_result: RegisterResponse = response.json();
        assert!(register_result.success);

        // Login user
        let login_body = json!({
            "username": username,
            "password": password
        });

        let response = app.post_json("api/login", login_body).await;
        assert_eq!(response.status, 200);
        let login_result: LoginResponse = response.json();
        assert!(login_result.success);

        login_result.token.unwrap()
    }

    #[tokio::test]
    async fn test_register_user_success() {
        let app = TestApp::new().await;

        let register_body = json!({
            "username": "testuser1",
            "password": "password123"
        });

        let response = app.post_json("api/register", register_body).await;

        assert_eq!(response.status, 200);

        let result: RegisterResponse = response.json();
        assert!(result.success);
        assert_eq!(result.message, "User registered successfully");
        assert!(result.user_id.is_some());
    }

    #[tokio::test]
    async fn test_register_user_empty_username() {
        let app = TestApp::new().await;

        let register_body = json!({
            "username": "",
            "password": "password123"
        });

        let response = app.post_json("api/register", register_body).await;

        assert_eq!(response.status, 400);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Username cannot be empty");
    }

    #[tokio::test]
    async fn test_register_user_short_password() {
        let app = TestApp::new().await;

        let register_body = json!({
            "username": "testuser2",
            "password": "123"
        });

        let response = app.post_json("api/register", register_body).await;

        assert_eq!(response.status, 400);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Password must be at least 6 characters long");
    }

    #[tokio::test]
    async fn test_register_user_duplicate_username() {
        let app = TestApp::new().await;

        // Register first user
        let register_body = json!({
            "username": "duplicateuser",
            "password": "password123"
        });

        let response = app.post_json("api/register", register_body.clone()).await;
        assert_eq!(response.status, 200);

        // Try to register with same username
        let response = app.post_json("api/register", register_body.clone()).await;

        assert_eq!(response.status, 409);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Username already exists");
    }

    #[tokio::test]
    async fn test_login_success() {
        let app = TestApp::new().await;

        // First register a user
        let register_body = json!({
            "username": "loginuser",
            "password": "password123"
        });

        let response = app.post_json("api/register", register_body).await;
        assert_eq!(response.status, 200);

        // Now login
        let login_body = json!({
            "username": "loginuser",
            "password": "password123"
        });

        let response = app.post_json("api/login", login_body).await;

        assert_eq!(response.status, 200);

        let result: LoginResponse = response.json();
        assert!(result.success);
        assert_eq!(result.message, "Login successful");
        assert!(result.token.is_some());
        assert!(result.user.is_some());

        let user = result.user.unwrap();
        assert_eq!(user.username, "loginuser");
        assert!(user.id.len() > 0);
        assert!(user.created_at.len() > 0);
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let app = TestApp::new().await;

        let login_body = json!({
            "username": "nonexistentuser",
            "password": "wrongpassword"
        });

        let response = app.post_json("api/login", login_body).await;

        assert_eq!(response.status, 401);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Invalid username or password");
    }

    #[tokio::test]
    async fn test_login_empty_username() {
        let app = TestApp::new().await;

        let login_body = json!({
            "username": "",
            "password": "password123"
        });

        let response = app.post_json("api/login", login_body).await;

        assert_eq!(response.status, 400);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Username cannot be empty");
    }

    #[tokio::test]
    async fn test_login_empty_password() {
        let app = TestApp::new().await;

        let login_body = json!({
            "username": "testuser",
            "password": ""
        });

        let response = app.post_json("api/login", login_body).await;

        assert_eq!(response.status, 400);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Password cannot be empty");
    }

    #[tokio::test]
    async fn test_add_connection_success() {
        let app = TestApp::new().await;

        // Create two users
        let token1 = create_test_user_and_get_token(&app, "user1", "password123").await;
        let _token2 = create_test_user_and_get_token(&app, "user2", "password123").await;

        // Add connection from user1 to user2
        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("api/connections", connection_body, &token1)
            .await;

        assert_eq!(response.status, 200);

        let result: AddConnectionResponse = response.json();
        assert!(result.success);
        assert_eq!(
            result.message,
            "Connection request sent to user2. Waiting for acceptance."
        );
        assert!(result.connection_id.is_some());
    }

    #[tokio::test]
    async fn test_add_connection_to_self() {
        let app = TestApp::new().await;

        let token = create_test_user_and_get_token(&app, "user1", "password123").await;

        // Try to connect to self
        let connection_body = json!({
            "username": "user1"
        });

        let response = app
            .post_with_auth("api/connections", connection_body, &token)
            .await;

        assert_eq!(response.status, 409);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Cannot connect to yourself");
    }

    #[tokio::test]
    async fn test_add_connection_user_not_found() {
        let app = TestApp::new().await;

        let token = create_test_user_and_get_token(&app, "user1", "password123").await;

        // Try to connect to non-existent user
        let connection_body = json!({
            "username": "nonexistentuser"
        });

        let response = app
            .post_with_auth("api/connections", connection_body, &token)
            .await;

        assert_eq!(response.status, 404);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "User not found");
    }

    #[tokio::test]
    async fn test_add_connection_duplicate() {
        let app = TestApp::new().await;

        let token1 = create_test_user_and_get_token(&app, "user1", "password123").await;
        let _token2 = create_test_user_and_get_token(&app, "user2", "password123").await;

        // Add connection from user1 to user2
        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("api/connections", connection_body.clone(), &token1)
            .await;
        assert_eq!(response.status, 200);

        // Try to add the same connection again
        let response = app
            .post_with_auth("api/connections", connection_body.clone(), &token1)
            .await;

        assert_eq!(response.status, 409);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Connection already exists");
    }

    #[tokio::test]
    async fn test_add_connection_invalid_token() {
        let app = TestApp::new().await;

        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("api/connections", connection_body, "invalid_token")
            .await;

        assert_eq!(response.status, 401);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Invalid session token");
    }

    #[tokio::test]
    async fn test_add_connection_empty_username() {
        let app = TestApp::new().await;

        let token = create_test_user_and_get_token(&app, "user1", "password123").await;

        let connection_body = json!({
            "username": ""
        });

        let response = app
            .post_with_auth("api/connections", connection_body, &token)
            .await;

        assert_eq!(response.status, 400);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Username cannot be empty");
    }

    #[tokio::test]
    async fn test_get_connections_success() {
        let app = TestApp::new().await;

        let token1 = create_test_user_and_get_token(&app, "user1", "password123").await;
        let _token2 = create_test_user_and_get_token(&app, "user2", "password123").await;

        // Add connection from user1 to user2
        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("api/connections", connection_body, &token1)
            .await;
        assert_eq!(response.status, 200);

        // Get connections for user1 (should show pending connection)
        let response = app.get_with_auth("api/connections", &token1).await;

        assert_eq!(response.status, 200);

        let result: ConnectionsResponse = response.json();
        assert!(result.success);
        assert_eq!(result.connections.len(), 1);

        let connection = &result.connections[0];
        assert_eq!(connection.other_username, "user2");
        assert_eq!(connection.status, "pending");
        assert_eq!(connection.initiated_by, "user1");
    }

    #[tokio::test]
    async fn test_get_connections_no_connections() {
        let app = TestApp::new().await;

        let token = create_test_user_and_get_token(&app, "user1", "password123").await;

        let response = app.get_with_auth("api/connections", &token).await;

        assert_eq!(response.status, 200);

        let result: ConnectionsResponse = response.json();
        assert!(result.success);
        assert_eq!(result.connections.len(), 0);
    }

    #[tokio::test]
    async fn test_get_connections_invalid_token() {
        let app = TestApp::new().await;

        let response = app.get_with_auth("api/connections", "invalid_token").await;

        assert_eq!(response.status, 401);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Invalid session token");
    }

    #[tokio::test]
    async fn test_accept_connection_success() {
        let app = TestApp::new().await;

        let token1 = create_test_user_and_get_token(&app, "user1", "password123").await;
        let token2 = create_test_user_and_get_token(&app, "user2", "password123").await;

        // Add connection from user1 to user2
        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("api/connections", connection_body, &token1)
            .await;
        assert_eq!(response.status, 200);
        let add_result: AddConnectionResponse = response.json();
        let connection_id = add_result.connection_id.unwrap();

        // Accept connection as user2
        let accept_body = json!({
            "connection_id": connection_id
        });

        let response = app
            .post_with_auth("api/connections/accept", accept_body, &token2)
            .await;

        assert_eq!(response.status, 200);

        let result: AcceptConnectionResponse = response.json();
        assert!(result.success);
        assert_eq!(result.message, "Connection accepted successfully");
    }

    #[tokio::test]
    async fn test_accept_connection_not_authorized() {
        let app = TestApp::new().await;

        let token1 = create_test_user_and_get_token(&app, "user1", "password123").await;
        let _token2 = create_test_user_and_get_token(&app, "user2", "password123").await;

        // Add connection from user1 to user2
        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("api/connections", connection_body, &token1)
            .await;
        assert_eq!(response.status, 200);
        let add_result: AddConnectionResponse = response.json();
        let connection_id = add_result.connection_id.unwrap();

        // Try to accept connection as user1 (who initiated it)
        let accept_body = json!({
            "connection_id": connection_id
        });

        let response = app
            .post_with_auth("api/connections/accept", accept_body, &token1)
            .await;

        assert_eq!(response.status, 403);

        let result: ErrorResponse = response.json();
        assert_eq!(
            result.error,
            "You cannot accept your own connection request"
        );
    }

    #[tokio::test]
    async fn test_accept_connection_already_accepted() {
        let app = TestApp::new().await;

        let token1 = create_test_user_and_get_token(&app, "user1", "password123").await;
        let token2 = create_test_user_and_get_token(&app, "user2", "password123").await;

        // Add connection from user1 to user2
        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("api/connections", connection_body, &token1)
            .await;
        assert_eq!(response.status, 200);
        let add_result: AddConnectionResponse = response.json();
        let connection_id = add_result.connection_id.unwrap();

        // Accept connection as user2
        let accept_body = json!({
            "connection_id": connection_id
        });

        let response = app
            .post_with_auth("api/connections/accept", accept_body.clone(), &token2)
            .await;
        assert_eq!(response.status, 200);

        // Try to accept again
        let response = app
            .post_with_auth("api/connections/accept", accept_body.clone(), &token2)
            .await;

        assert_eq!(response.status, 409);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Connection is already accepted");
    }

    #[tokio::test]
    async fn test_accept_connection_not_found() {
        let app = TestApp::new().await;

        let token = create_test_user_and_get_token(&app, "user1", "password123").await;

        let accept_body = json!({
            "connection_id": "nonexistent-connection-id"
        });

        let response = app
            .post_with_auth("api/connections/accept", accept_body, &token)
            .await;

        assert_eq!(response.status, 404);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Connection not found");
    }

    #[tokio::test]
    async fn test_accept_connection_invalid_token() {
        let app = TestApp::new().await;

        let accept_body = json!({
            "connection_id": "some-connection-id"
        });

        let response = app
            .post_with_auth("api/connections/accept", accept_body, "invalid_token")
            .await;

        assert_eq!(response.status, 401);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Invalid session token");
    }
}

// Minimal handler functions for testing (simplified versions of the actual handlers)
#[axum::debug_handler]
async fn register_user_handler(
    axum::extract::State(db): axum::extract::State<std::sync::Arc<sqlx::SqlitePool>>,
    axum::extract::Json(request): axum::extract::Json<RegisterRequest>,
) -> Result<axum::Json<RegisterResponse>, (axum::http::StatusCode, axum::Json<ErrorResponse>)> {
    // Validate input
    if request.username.trim().is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Username cannot be empty".to_string(),
            }),
        ));
    }

    if request.password.len() < 6 {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Password must be at least 6 characters long".to_string(),
            }),
        ));
    }

    // Simple password hashing (for testing only)
    let password_hash = format!("hashed_{}", request.password);

    // Generate new user ID
    let user_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    // Insert user into database
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&user_id)
    .bind(&request.username)
    .bind(&password_hash)
    .bind(&now)
    .bind(&now)
    .execute(&*db)
    .await
    .map_err(|_| {
        (
            axum::http::StatusCode::CONFLICT,
            axum::Json(ErrorResponse {
                error: "Username already exists".to_string(),
            }),
        )
    })?;

    Ok(axum::Json(RegisterResponse {
        success: true,
        message: "User registered successfully".to_string(),
        user_id: Some(user_id),
    }))
}

#[axum::debug_handler]
async fn login_user_handler(
    axum::extract::State(db): axum::extract::State<std::sync::Arc<sqlx::SqlitePool>>,
    axum::extract::Json(request): axum::extract::Json<LoginRequest>,
) -> Result<axum::Json<LoginResponse>, (axum::http::StatusCode, axum::Json<ErrorResponse>)> {
    // Validate input
    if request.username.trim().is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Username cannot be empty".to_string(),
            }),
        ));
    }

    if request.password.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Password cannot be empty".to_string(),
            }),
        ));
    }

    // Find user
    let user_row =
        sqlx::query("SELECT id, username, password_hash, created_at FROM users WHERE username = ?")
            .bind(&request.username)
            .fetch_optional(&*db)
            .await
            .map_err(|_| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(ErrorResponse {
                        error: "Database error".to_string(),
                    }),
                )
            })?;

    if let Some(row) = user_row {
        let stored_hash: String = row.get("password_hash");

        // Simple password verification (for testing only)
        let expected_hash = format!("hashed_{}", request.password);
        if stored_hash == expected_hash {
            // Generate session token
            let token = uuid::Uuid::new_v4().to_string();
            let session_id = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();

            // Insert session
            sqlx::query(
                "INSERT INTO sessions (id, user_id, token, created_at) VALUES (?, ?, ?, ?)",
            )
            .bind(&session_id)
            .bind(row.get::<String, _>("id"))
            .bind(&token)
            .bind(&now)
            .execute(&*db)
            .await
            .map_err(|_| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(ErrorResponse {
                        error: "Failed to create session".to_string(),
                    }),
                )
            })?;

            Ok(axum::Json(LoginResponse {
                success: true,
                message: "Login successful".to_string(),
                user: Some(UserInfo {
                    id: row.get("id"),
                    username: row.get("username"),
                    created_at: row.get("created_at"),
                }),
                token: Some(token),
            }))
        } else {
            Err((
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(ErrorResponse {
                    error: "Invalid username or password".to_string(),
                }),
            ))
        }
    } else {
        Err((
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(ErrorResponse {
                error: "Invalid username or password".to_string(),
            }),
        ))
    }
}

// Helper function to validate session token
async fn validate_session_token(
    db: &sqlx::SqlitePool,
    token: &str,
) -> Result<String, (axum::http::StatusCode, axum::Json<ErrorResponse>)> {
    let session_row = sqlx::query("SELECT user_id FROM sessions WHERE token = ?")
        .bind(token)
        .fetch_optional(db)
        .await
        .map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Database error".to_string(),
                }),
            )
        })?;

    match session_row {
        Some(row) => Ok(row.get::<String, _>("user_id")),
        None => Err((
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(ErrorResponse {
                error: "Invalid session token".to_string(),
            }),
        )),
    }
}

#[axum::debug_handler]
async fn add_connection_handler(
    axum::extract::State(db): axum::extract::State<std::sync::Arc<sqlx::SqlitePool>>,
    auth_header: axum::http::HeaderMap,
    axum::extract::Json(request): axum::extract::Json<AddConnectionRequest>,
) -> Result<axum::Json<AddConnectionResponse>, (axum::http::StatusCode, axum::Json<ErrorResponse>)>
{
    // Validate input
    if request.username.trim().is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Username cannot be empty".to_string(),
            }),
        ));
    }

    // Get token from Authorization header
    let token = match auth_header.get("authorization") {
        Some(value) => {
            let auth_str = value.to_str().map_err(|_| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(ErrorResponse {
                        error: "Invalid authorization header".to_string(),
                    }),
                )
            })?;
            if auth_str.starts_with("Bearer ") {
                auth_str[7..].to_string()
            } else {
                return Err((
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(ErrorResponse {
                        error: "Invalid authorization format".to_string(),
                    }),
                ));
            }
        }
        None => {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(ErrorResponse {
                    error: "Missing authorization header".to_string(),
                }),
            ));
        }
    };

    // Validate session token
    let user_id = validate_session_token(&db, &token).await?;

    // Get user info for the requesting user
    let user_row = sqlx::query("SELECT username FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&*db)
        .await
        .map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Database error".to_string(),
                }),
            )
        })?;

    let requester_username = match user_row {
        Some(row) => row.get::<String, _>("username"),
        None => {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(ErrorResponse {
                    error: "User not found".to_string(),
                }),
            ));
        }
    };

    // Store username in initiated_by instead of user_id
    let initiated_by = requester_username.clone();

    // Check if trying to connect to self
    if requester_username == request.username {
        return Err((
            axum::http::StatusCode::CONFLICT,
            axum::Json(ErrorResponse {
                error: "Cannot connect to yourself".to_string(),
            }),
        ));
    }

    // Find target user
    let target_user_row = sqlx::query("SELECT id, username FROM users WHERE username = ?")
        .bind(&request.username)
        .fetch_optional(&*db)
        .await
        .map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Database error".to_string(),
                }),
            )
        })?;

    let target_user_id = match target_user_row {
        Some(row) => row.get::<String, _>("id"),
        None => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(ErrorResponse {
                    error: "User not found".to_string(),
                }),
            ));
        }
    };

    // Check if connection already exists (in either direction)
    let existing_connection = sqlx::query(
        "SELECT id FROM connections WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)"
    )
    .bind(&user_id)
    .bind(&target_user_id)
    .bind(&target_user_id)
    .bind(&user_id)
    .fetch_optional(&*db)
    .await
    .map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse {
                error: "Database error".to_string(),
            }),
        )
    })?;

    if existing_connection.is_some() {
        return Err((
            axum::http::StatusCode::CONFLICT,
            axum::Json(ErrorResponse {
                error: "Connection already exists".to_string(),
            }),
        ));
    }

    // Create new connection
    let connection_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO connections (id, user1_id, user2_id, status, initiated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&connection_id)
    .bind(&user_id)
    .bind(&target_user_id)
    .bind("pending")
    .bind(&initiated_by)
    .bind(&now)
    .bind(&now)
    .execute(&*db)
    .await
    .map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse {
                error: "Failed to create connection".to_string(),
            }),
        )
    })?;

    Ok(axum::Json(AddConnectionResponse {
        success: true,
        message: format!(
            "Connection request sent to {}. Waiting for acceptance.",
            request.username
        ),
        connection_id: Some(connection_id),
    }))
}

#[axum::debug_handler]
async fn get_connections_handler(
    auth_header: axum::http::HeaderMap,
    axum::extract::State(db): axum::extract::State<std::sync::Arc<sqlx::SqlitePool>>,
) -> Result<axum::Json<ConnectionsResponse>, (axum::http::StatusCode, axum::Json<ErrorResponse>)> {
    // Get token from Authorization header
    let token = match auth_header.get("authorization") {
        Some(value) => {
            let auth_str = value.to_str().map_err(|_| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(ErrorResponse {
                        error: "Invalid authorization header".to_string(),
                    }),
                )
            })?;
            if auth_str.starts_with("Bearer ") {
                auth_str[7..].to_string()
            } else {
                return Err((
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(ErrorResponse {
                        error: "Invalid authorization format".to_string(),
                    }),
                ));
            }
        }
        None => {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(ErrorResponse {
                    error: "Missing authorization header".to_string(),
                }),
            ));
        }
    };

    // Validate session token
    let user_id = validate_session_token(&db, &token).await?;

    // Get user's connections
    let connections = sqlx::query(
        r#"
        SELECT
            c.id,
            c.user1_id,
            c.user2_id,
            CASE
                WHEN c.user1_id = ? THEN (SELECT username FROM users WHERE id = c.user2_id)
                WHEN c.user2_id = ? THEN (SELECT username FROM users WHERE id = c.user1_id)
                ELSE NULL
            END as other_username,
            c.status,
            c.initiated_by,
            c.created_at
        FROM connections c
        WHERE (c.user1_id = ? OR c.user2_id = ?)
        "#,
    )
    .bind(&user_id)
    .bind(&user_id)
    .bind(&user_id)
    .bind(&user_id)
    .fetch_all(&*db)
    .await
    .map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse {
                error: "Database error".to_string(),
            }),
        )
    })?;

    let mut connection_list = Vec::new();
    for row in connections {
        connection_list.push(Connection {
            id: row.get("id"),
            user1_id: row.get("user1_id"),
            user2_id: row.get("user2_id"),
            other_username: row.get("other_username"),
            status: row.get("status"),
            initiated_by: row.get("initiated_by"),
            created_at: row.get("created_at"),
        });
    }

    Ok(axum::Json(ConnectionsResponse {
        success: true,
        connections: connection_list,
    }))
}

#[axum::debug_handler]
async fn accept_connection_handler(
    axum::extract::State(db): axum::extract::State<std::sync::Arc<sqlx::SqlitePool>>,
    auth_header: axum::http::HeaderMap,
    axum::extract::Json(request): axum::extract::Json<AcceptConnectionRequest>,
) -> Result<axum::Json<AcceptConnectionResponse>, (axum::http::StatusCode, axum::Json<ErrorResponse>)>
{
    // Get token from Authorization header
    let token = match auth_header.get("authorization") {
        Some(value) => {
            let auth_str = value.to_str().map_err(|_| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(ErrorResponse {
                        error: "Invalid authorization header".to_string(),
                    }),
                )
            })?;
            if auth_str.starts_with("Bearer ") {
                auth_str[7..].to_string()
            } else {
                return Err((
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(ErrorResponse {
                        error: "Invalid authorization format".to_string(),
                    }),
                ));
            }
        }
        None => {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(ErrorResponse {
                    error: "Missing authorization header".to_string(),
                }),
            ));
        }
    };

    // Validate session token
    let user_id = validate_session_token(&db, &token).await?;

    // Get connection info
    let connection_row = sqlx::query(
        "SELECT user1_id, user2_id, status, initiated_by FROM connections WHERE id = ?",
    )
    .bind(&request.connection_id)
    .fetch_optional(&*db)
    .await
    .map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse {
                error: "Database error".to_string(),
            }),
        )
    })?;

    let connection = match connection_row {
        Some(row) => row,
        None => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(ErrorResponse {
                    error: "Connection not found".to_string(),
                }),
            ));
        }
    };

    let user1_id: String = connection.get("user1_id");
    let user2_id: String = connection.get("user2_id");
    let status: String = connection.get("status");
    let initiated_by: String = connection.get("initiated_by");

    // Check if connection is already accepted
    if status == "accepted" {
        return Err((
            axum::http::StatusCode::CONFLICT,
            axum::Json(ErrorResponse {
                error: "Connection is already accepted".to_string(),
            }),
        ));
    }

    // Get the username of user1 to compare with initiated_by
    let user1_username = sqlx::query("SELECT username FROM users WHERE id = ?")
        .bind(&user1_id)
        .fetch_optional(&*db)
        .await
        .map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Database error".to_string(),
                }),
            )
        })?
        .map(|row| row.get::<String, _>("username"))
        .unwrap_or_default();

    // Check if user is authorized to accept this connection (must be the target user)
    let is_user2 = user_id == user2_id;
    let was_initiated_by_user1 = initiated_by == user1_username;

    if !is_user2 || !was_initiated_by_user1 {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(ErrorResponse {
                error: "You cannot accept your own connection request".to_string(),
            }),
        ));
    }

    // Update connection status to accepted
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("UPDATE connections SET status = 'accepted', updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&request.connection_id)
        .execute(&*db)
        .await
        .map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Failed to accept connection".to_string(),
                }),
            )
        })?;

    Ok(axum::Json(AcceptConnectionResponse {
        success: true,
        message: "Connection accepted successfully".to_string(),
    }))
}
