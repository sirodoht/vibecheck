use axum::{
    body::Body,
    http::{Method, Request},
};
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tower::{Service, ServiceExt}; // for `call`, `oneshot`, and `ready`

use yoapi::{
    AcceptConnectionResponse, AddConnectionResponse, ConnectionsResponse, Database, ErrorResponse,
    LoginResponse, RegisterResponse, SendYoResponse, YoMessagesResponse, create_app,
};

pub struct TestApp {
    pub app: axum::Router,
    _temp_dir: TempDir,
}

impl TestApp {
    pub async fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // Use an in-memory database for testing
        let database_url = "sqlite::memory:";
        let db = Database::new(database_url)
            .await
            .expect("Failed to create test database");

        // Run migrations
        db.run_migrations().await.expect("Failed to run migrations");

        let app_state = Arc::new(db);
        let app = create_app(app_state);

        TestApp {
            app,
            _temp_dir: temp_dir,
        }
    }

    pub async fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        auth_token: Option<&str>,
    ) -> TestResponse {
        let mut request_builder = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");

        if let Some(token) = auth_token {
            request_builder = request_builder.header("authorization", format!("Bearer {}", token));
        }

        let body = match body {
            Some(json_body) => Body::from(json_body.to_string()),
            None => Body::empty(),
        };

        let request = request_builder.body(body).expect("Failed to build request");

        let response = ServiceExt::<Request<Body>>::ready(&mut self.app)
            .await
            .expect("Service not ready")
            .call(request)
            .await
            .expect("Failed to make request");

        let status = response.status();
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("Failed to read response body")
            .to_bytes();
        let body =
            String::from_utf8(body_bytes.to_vec()).expect("Response body is not valid UTF-8");

        TestResponse { status, body }
    }

    pub async fn post(&mut self, path: &str, body: serde_json::Value) -> TestResponse {
        self.request(Method::POST, path, Some(body), None).await
    }

    pub async fn get(&mut self, path: &str) -> TestResponse {
        self.request(Method::GET, path, None, None).await
    }

    pub async fn post_with_auth(
        &mut self,
        path: &str,
        body: serde_json::Value,
        token: &str,
    ) -> TestResponse {
        self.request(Method::POST, path, Some(body), Some(token))
            .await
    }

    pub async fn get_with_auth(&mut self, path: &str, token: &str) -> TestResponse {
        self.request(Method::GET, path, None, Some(token)).await
    }
}

pub struct TestResponse {
    pub status: axum::http::StatusCode,
    pub body: String,
}

impl TestResponse {
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> T {
        serde_json::from_str(&self.body).expect("Failed to parse JSON response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    // Helper function to create a test user and get their token
    async fn create_test_user_and_get_token(
        app: &mut TestApp,
        username: &str,
        password: &str,
    ) -> String {
        // Register user
        let register_body = json!({
            "username": username,
            "password": password
        });

        let response = app.post("/api/register", register_body).await;
        assert_eq!(response.status, StatusCode::OK);
        let _register_result: RegisterResponse = response.json();

        // Login user
        let login_body = json!({
            "username": username,
            "password": password
        });

        let response = app.post("/api/login", login_body).await;
        assert_eq!(response.status, StatusCode::OK);
        let login_result: LoginResponse = response.json();

        login_result.token.unwrap()
    }

    #[tokio::test]
    async fn test_register_user_success() {
        let mut app = TestApp::new().await;

        let register_body = json!({
            "username": "testuser1",
            "password": "password123"
        });

        let response = app.post("/api/register", register_body).await;

        assert_eq!(response.status, StatusCode::OK);
        let _result: RegisterResponse = response.json();
    }

    #[tokio::test]
    async fn test_register_user_empty_username() {
        let mut app = TestApp::new().await;

        let register_body = json!({
            "username": "",
            "password": "password123"
        });

        let response = app.post("/api/register", register_body).await;

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Username cannot be empty");
    }

    #[tokio::test]
    async fn test_register_user_short_password() {
        let mut app = TestApp::new().await;

        let register_body = json!({
            "username": "testuser2",
            "password": "123"
        });

        let response = app.post("/api/register", register_body).await;

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Password must be at least 6 characters long");
    }

    #[tokio::test]
    async fn test_register_user_duplicate_username() {
        let mut app = TestApp::new().await;

        let register_body = json!({
            "username": "duplicateuser",
            "password": "password123"
        });

        // Register first user
        let response = app.post("/api/register", register_body.clone()).await;
        assert_eq!(response.status, StatusCode::OK);

        // Try to register with same username
        let response = app.post("/api/register", register_body).await;
        assert_eq!(response.status, StatusCode::CONFLICT);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Username already exists");
    }

    #[tokio::test]
    async fn test_login_success() {
        let mut app = TestApp::new().await;

        // First register a user
        let register_body = json!({
            "username": "loginuser",
            "password": "password123"
        });

        let response = app.post("/api/register", register_body).await;
        assert_eq!(response.status, StatusCode::OK);

        // Now login
        let login_body = json!({
            "username": "loginuser",
            "password": "password123"
        });

        let response = app.post("/api/login", login_body).await;
        assert_eq!(response.status, StatusCode::OK);

        let result: LoginResponse = response.json();
        assert!(result.token.is_some());
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let mut app = TestApp::new().await;

        let login_body = json!({
            "username": "nonexistentuser",
            "password": "wrongpassword"
        });

        let response = app.post("/api/login", login_body).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Invalid username or password");
    }

    #[tokio::test]
    async fn test_login_empty_username() {
        let mut app = TestApp::new().await;

        let login_body = json!({
            "username": "",
            "password": "password123"
        });

        let response = app.post("/api/login", login_body).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Username cannot be empty");
    }

    #[tokio::test]
    async fn test_add_connection_success() {
        let mut app = TestApp::new().await;

        // Create two users
        let token1 = create_test_user_and_get_token(&mut app, "user1", "password123").await;
        let _token2 = create_test_user_and_get_token(&mut app, "user2", "password123").await;

        // Add connection from user1 to user2
        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("/api/connections/request", connection_body, &token1)
            .await;
        assert_eq!(response.status, StatusCode::OK);

        let _result: AddConnectionResponse = response.json();
    }

    #[tokio::test]
    async fn test_add_connection_to_self() {
        let mut app = TestApp::new().await;

        let token = create_test_user_and_get_token(&mut app, "user1", "password123").await;

        let connection_body = json!({
            "username": "user1"
        });

        let response = app
            .post_with_auth("/api/connections/request", connection_body, &token)
            .await;
        assert_eq!(response.status, StatusCode::CONFLICT);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Cannot connect to yourself");
    }

    #[tokio::test]
    async fn test_add_connection_user_not_found() {
        let mut app = TestApp::new().await;

        let token = create_test_user_and_get_token(&mut app, "user1", "password123").await;

        let connection_body = json!({
            "username": "nonexistentuser"
        });

        let response = app
            .post_with_auth("/api/connections/request", connection_body, &token)
            .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "User not found");
    }

    #[tokio::test]
    async fn test_get_connections_success() {
        let mut app = TestApp::new().await;

        let token1 = create_test_user_and_get_token(&mut app, "user1", "password123").await;
        let _token2 = create_test_user_and_get_token(&mut app, "user2", "password123").await;

        // Add connection from user1 to user2
        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("/api/connections/request", connection_body, &token1)
            .await;
        assert_eq!(response.status, StatusCode::OK);

        // Get connections for user1
        let response = app.get_with_auth("/api/connections", &token1).await;
        assert_eq!(response.status, StatusCode::OK);

        let result: ConnectionsResponse = response.json();
        assert_eq!(result.connections.len(), 1);

        let connection = &result.connections[0];
        assert_eq!(connection.other, "user2");
        assert_eq!(connection.status, "pending");
    }

    #[tokio::test]
    async fn test_accept_connection_success() {
        let mut app = TestApp::new().await;

        let token1 = create_test_user_and_get_token(&mut app, "user1", "password123").await;
        let token2 = create_test_user_and_get_token(&mut app, "user2", "password123").await;

        // Add connection from user1 to user2
        let connection_body = json!({
            "username": "user2"
        });

        let response = app
            .post_with_auth("/api/connections/request", connection_body, &token1)
            .await;
        assert_eq!(response.status, StatusCode::OK);

        // Accept connection as user2
        let accept_body = json!({
            "username": "user1"
        });

        let response = app
            .post_with_auth("/api/connections/accept", accept_body, &token2)
            .await;
        assert_eq!(response.status, StatusCode::OK);

        let _result: AcceptConnectionResponse = response.json();

        // Verify connection is now accepted
        let response = app.get_with_auth("/api/connections", &token1).await;
        let result: ConnectionsResponse = response.json();
        assert_eq!(result.connections[0].status, "accepted");
    }

    #[tokio::test]
    async fn test_send_yo_success() {
        let mut app = TestApp::new().await;

        // Create two users and make them friends
        let token1 = create_test_user_and_get_token(&mut app, "user1", "password123").await;
        let token2 = create_test_user_and_get_token(&mut app, "user2", "password123").await;

        // Add and accept connection
        let connection_body = json!({"username": "user2"});
        let response = app
            .post_with_auth("/api/connections/request", connection_body, &token1)
            .await;
        assert_eq!(response.status, StatusCode::OK);

        let accept_body = json!({"username": "user1"});
        let response = app
            .post_with_auth("/api/connections/accept", accept_body, &token2)
            .await;
        assert_eq!(response.status, StatusCode::OK);

        // Send yo from user1 to user2
        let yo_body = json!({"username": "user2"});
        let response = app.post_with_auth("/api/yo", yo_body, &token1).await;
        assert_eq!(response.status, StatusCode::OK);

        let _result: SendYoResponse = response.json();
    }

    #[tokio::test]
    async fn test_send_yo_to_non_friend() {
        let mut app = TestApp::new().await;

        let token1 = create_test_user_and_get_token(&mut app, "user1", "password123").await;
        let _token2 = create_test_user_and_get_token(&mut app, "user2", "password123").await;

        // Try to send yo without being friends
        let yo_body = json!({"username": "user2"});
        let response = app.post_with_auth("/api/yo", yo_body, &token1).await;
        assert_eq!(response.status, StatusCode::CONFLICT);

        let result: ErrorResponse = response.json();
        assert_eq!(
            result.error,
            "You can only send yo messages to your friends"
        );
    }

    #[tokio::test]
    async fn test_get_yo_messages_success() {
        let mut app = TestApp::new().await;

        // Create two users and make them friends
        let token1 = create_test_user_and_get_token(&mut app, "user1", "password123").await;
        let token2 = create_test_user_and_get_token(&mut app, "user2", "password123").await;

        // Add and accept connection
        let connection_body = json!({"username": "user2"});
        let response = app
            .post_with_auth("/api/connections/request", connection_body, &token1)
            .await;
        assert_eq!(response.status, StatusCode::OK);

        let accept_body = json!({"username": "user1"});
        let response = app
            .post_with_auth("/api/connections/accept", accept_body, &token2)
            .await;
        assert_eq!(response.status, StatusCode::OK);

        // Send yo from user1 to user2
        let yo_body = json!({"username": "user2"});
        let response = app.post_with_auth("/api/yo", yo_body, &token1).await;
        assert_eq!(response.status, StatusCode::OK);

        // Get yo messages for user2
        let response = app.get_with_auth("/api/yo", &token2).await;
        assert_eq!(response.status, StatusCode::OK);

        let result: YoMessagesResponse = response.json();
        assert_eq!(result.messages.len(), 1);

        let message = &result.messages[0];
        assert_eq!(message.from, "user1");
        assert_eq!(message.to, "user2");
    }

    #[tokio::test]
    async fn test_invalid_auth_token() {
        let mut app = TestApp::new().await;

        let response = app.get_with_auth("/api/connections", "invalid_token").await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        let result: ErrorResponse = response.json();
        assert_eq!(result.error, "Invalid session token");
    }
}
