use askama::Template;
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};

pub mod database;
pub use database::Database;

// Application state
pub type AppState = Arc<Database>;

// Template structs
#[derive(Serialize)]
pub struct UserPair {
    pub from_username: String,
    pub to_username: String,
    pub connection_exists: bool,
}

#[derive(Template)]
#[template(path = "swagger.html")]
pub struct SwaggerTemplate;

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub users: Vec<User>,
    pub next_user_name: String,
    pub users_with_friends: Vec<UserWithFriends>,
    pub total_users_with_friends: i64,
    pub pending_connections: Vec<AdminConnection>,
    pub accepted_connections: Vec<AdminConnection>,
    pub user_pairs: Vec<UserPair>,
}

#[derive(Serialize)]
pub struct UserWithFriends {
    pub username: String,
    pub friends: Vec<Friend>,
}

#[derive(Serialize)]
pub struct Friend {
    pub username: String,
    pub connection_id: String,
    pub created_at: String,
    pub status: String,
}

#[derive(Serialize, Clone)]
pub struct AdminConnection {
    pub id: String,
    pub initiator_username: String,
    pub target_username: String,
    pub status: String,
    pub created_at: String,
}

// User-related structures for API
#[derive(sqlx::FromRow, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip)] // Never serialize password hash
    pub password_hash: String,
    pub created_at: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// The username for the new account
    pub username: String,
    /// The password for the new account (minimum 6 characters)
    pub password: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RegisterResponse {}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    /// The username to authenticate
    pub username: String,
    /// The password to authenticate
    pub password: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LoginResponse {
    /// Authentication token
    pub token: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct UserInfo {
    /// Unique user ID
    pub id: String,
    /// Username
    pub username: String,
    /// Timestamp when the user was created
    pub created_at: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// Error message describing what went wrong
    pub error: String,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct Connection {
    /// Username of the user who initiated the connection request
    pub initiator: String,
    /// Username of the user who did not initiate the connection
    pub other: String,
    /// Status of the connection (pending or accepted)
    pub status: String,
    /// Timestamp when the connection was created
    pub created_at: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AddConnectionRequest {
    /// Username of the user to send a connection request to
    pub username: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AddConnectionResponse {}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ConnectionsResponse {
    /// List of user connections
    pub connections: Vec<Connection>,
}

#[derive(Deserialize, ToSchema)]
pub struct AcceptConnectionRequest {
    /// Username of the user whose connection request to accept
    pub username: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AcceptConnectionResponse {}

#[derive(Deserialize, ToSchema)]
pub struct SendYoRequest {
    /// Username of the friend to send yo to
    pub username: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SendYoResponse {}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct YoMessagesResponse {
    /// List of yo messages
    pub messages: Vec<YoMessageInfo>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct YoMessageInfo {
    /// Unique message ID
    pub id: String,
    /// Username who sent the yo
    pub from: String,
    /// Username who received the yo
    pub to: String,
    /// Timestamp when the yo was sent
    pub sent_at: String,
}

// Web Handler functions
pub async fn swagger() -> impl IntoResponse {
    let template = SwaggerTemplate;
    Html(template.render().unwrap())
}

pub async fn dashboard(State(db): State<AppState>) -> impl IntoResponse {
    let users = db.get_all_users().await.unwrap_or_default();

    // Calculate next user name
    let user_count = users.len();
    let next_user_name = format!("user{}", user_count + 1);

    // Get users with friends for connection display
    let users_with_friends = db.get_users_with_friends().await.unwrap_or_default();
    let total_users_with_friends = users_with_friends.len() as i64;

    // Get admin connections
    let admin_connections = db.get_admin_connections().await.unwrap_or_default();
    let pending_connections: Vec<AdminConnection> = admin_connections
        .iter()
        .filter(|c| c.status == "pending")
        .cloned()
        .collect();
    let accepted_connections: Vec<AdminConnection> = admin_connections
        .iter()
        .filter(|c| c.status == "accepted")
        .cloned()
        .collect();

    // Create user pairs with connection status
    let mut user_pairs = Vec::new();
    for user1 in &users {
        for user2 in &users {
            if user1.username != user2.username {
                // Check if any connection exists between these users (in either direction)
                let connection_exists = admin_connections.iter().any(|conn| {
                    (conn.initiator_username == user1.username
                        && conn.target_username == user2.username)
                        || (conn.initiator_username == user2.username
                            && conn.target_username == user1.username)
                });

                user_pairs.push(UserPair {
                    from_username: user1.username.clone(),
                    to_username: user2.username.clone(),
                    connection_exists,
                });
            }
        }
    }

    let template = DashboardTemplate {
        users,
        next_user_name,
        users_with_friends,
        total_users_with_friends,
        pending_connections,
        accepted_connections,
        user_pairs,
    };
    Html(template.render().unwrap())
}

// API Handler functions
#[utoipa::path(
    post,
    path = "/api/register",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "User registered successfully", body = RegisterResponse),
        (status = 400, description = "Bad request (invalid input)", body = ErrorResponse),
        (status = 409, description = "Username already exists", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn register_user(
    State(db): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate input
    if request.username.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username cannot be empty".to_string(),
            }),
        ));
    }

    if request.password.len() < 6 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Password must be at least 6 characters long".to_string(),
            }),
        ));
    }

    // Attempt to create user
    match db.create_user(&request.username, &request.password).await {
        Ok(_) => Ok(Json(RegisterResponse {})),
        Err(e) => {
            if e.to_string().contains("already exists") {
                Err((
                    StatusCode::CONFLICT,
                    Json(ErrorResponse {
                        error: "Username already exists".to_string(),
                    }),
                ))
            } else {
                eprintln!("User registration error: {}", e);
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal server error".to_string(),
                    }),
                ))
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 400, description = "Bad request (invalid input)", body = ErrorResponse),
        (status = 401, description = "Invalid username or password", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn login_user(
    State(db): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate input
    if request.username.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username cannot be empty".to_string(),
            }),
        ));
    }

    if request.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Password cannot be empty".to_string(),
            }),
        ));
    }

    // Authenticate user and create session
    let user = match db.verify_user(&request.username, &request.password).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid username or password".to_string(),
                }),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Authentication failed".to_string(),
                }),
            ));
        }
    };

    // Create and store session token in database
    let token = match db.create_session(&user.id).await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Session creation error: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Could not create session".to_string(),
                }),
            ));
        }
    };

    Ok(Json(LoginResponse { token: Some(token) }))
}

// Helper function to extract token from Authorization header
pub fn extract_token_from_headers(headers: &HeaderMap) -> Result<String, String> {
    let auth_header = headers
        .get("Authorization")
        .ok_or("Missing Authorization header")?
        .to_str()
        .map_err(|_| "Invalid Authorization header")?;

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        Ok(token.to_string())
    } else {
        Err("Invalid Authorization format. Expected 'Bearer <token>'".to_string())
    }
}

// Authenticated endpoint to add a connection/friend
#[utoipa::path(
    post,
    path = "/api/connections",
    request_body = AddConnectionRequest,
    responses(
        (status = 200, description = "Connection request sent successfully", body = AddConnectionResponse),
        (status = 400, description = "Bad request (invalid input)", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Target user not found", body = ErrorResponse),
        (status = 409, description = "Connection already exists or cannot connect to self", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Connections",
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn request_connection(
    State(db): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AddConnectionRequest>,
) -> Result<Json<AddConnectionResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Extract and validate session token
    let token = match extract_token_from_headers(&headers) {
        Ok(token) => token,
        Err(e) => return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: e }))),
    };

    // Validate session and get user
    let user = match db.validate_session(&token).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid session token".to_string(),
                }),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Session validation failed".to_string(),
                }),
            ));
        }
    };

    // Validate input
    if request.username.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username cannot be empty".to_string(),
            }),
        ));
    }

    // Create the connection
    match db.create_connection(&user.id, &request.username).await {
        Ok(_) => Ok(Json(AddConnectionResponse {})),
        Err(e) => {
            let error_msg = e.to_string();
            let status_code = if error_msg.contains("User not found") {
                StatusCode::NOT_FOUND
            } else if error_msg.contains("Connection already exists")
                || error_msg.contains("Cannot connect to yourself")
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            Err((status_code, Json(ErrorResponse { error: error_msg })))
        }
    }
}

// Authenticated endpoint to get user's connections
#[utoipa::path(
    get,
    path = "/api/connections",
    responses(
        (status = 200, description = "Successfully retrieved user connections", body = ConnectionsResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Connections",
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_connections(
    State(db): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ConnectionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Extract and validate session token
    let token = match extract_token_from_headers(&headers) {
        Ok(token) => token,
        Err(e) => return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: e }))),
    };

    // Validate session and get user
    let user = match db.validate_session(&token).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid session token".to_string(),
                }),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Session validation failed".to_string(),
                }),
            ));
        }
    };

    // Get user's connections
    match db.get_user_connections(&user.id).await {
        Ok(connections) => Ok(Json(ConnectionsResponse { connections })),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to retrieve connections".to_string(),
            }),
        )),
    }
}

// Authenticated endpoint to accept a pending connection
#[utoipa::path(
    post,
    path = "/api/connections/accept",
    request_body = AcceptConnectionRequest,
    responses(
        (status = 200, description = "Connection accepted successfully", body = AcceptConnectionResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Not authorized to accept this connection", body = ErrorResponse),
        (status = 404, description = "User not found or no pending connection from that user", body = ErrorResponse),
        (status = 409, description = "Connection already accepted", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Connections",
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn accept_connection(
    State(db): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AcceptConnectionRequest>,
) -> Result<Json<AcceptConnectionResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Extract and validate session token
    let token = match extract_token_from_headers(&headers) {
        Ok(token) => token,
        Err(e) => return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: e }))),
    };

    // Validate session and get user
    let user = match db.validate_session(&token).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid session token".to_string(),
                }),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Session validation failed".to_string(),
                }),
            ));
        }
    };

    // Validate input
    if request.username.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username cannot be empty".to_string(),
            }),
        ));
    }

    // Accept the connection
    match db
        .accept_connection_by_username(&user.id, &request.username)
        .await
    {
        Ok(()) => Ok(Json(AcceptConnectionResponse {})),
        Err(e) => {
            let error_msg = e.to_string();
            let status_code = if error_msg.contains("User not found")
                || error_msg.contains("Connection not found")
                || error_msg.contains("not authorized")
            {
                StatusCode::NOT_FOUND
            } else if error_msg.contains("already accepted") {
                StatusCode::CONFLICT
            } else if error_msg.contains("cannot accept your own") {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            Err((status_code, Json(ErrorResponse { error: error_msg })))
        }
    }
}

// Yo Handler functions
#[utoipa::path(
    post,
    path = "/api/yo",
    request_body = SendYoRequest,
    responses(
        (status = 200, description = "Yo sent successfully", body = SendYoResponse),
        (status = 400, description = "Bad request (invalid input)", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 409, description = "Cannot send yo to yourself or not friends", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Yo Messages",
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn send_yo(
    State(db): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SendYoRequest>,
) -> Result<Json<SendYoResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Extract and validate session token
    let token = match extract_token_from_headers(&headers) {
        Ok(token) => token,
        Err(e) => return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: e }))),
    };

    // Validate session and get user
    let user = match db.validate_session(&token).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid session token".to_string(),
                }),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Session validation failed".to_string(),
                }),
            ));
        }
    };

    // Validate input
    if request.username.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username cannot be empty".to_string(),
            }),
        ));
    }

    // Send the yo message
    match db.create_yo_message(&user.id, &request.username).await {
        Ok(_) => Ok(Json(SendYoResponse {})),
        Err(e) => {
            let error_msg = e.to_string();
            let status_code = if error_msg.contains("User not found") {
                StatusCode::NOT_FOUND
            } else if error_msg.contains("Cannot send yo to yourself")
                || error_msg.contains("only send yo messages to your friends")
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            Err((status_code, Json(ErrorResponse { error: error_msg })))
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/yo",
    responses(
        (status = 200, description = "Successfully retrieved yo messages", body = YoMessagesResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Yo Messages",
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_yo_messages(
    State(db): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<YoMessagesResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Extract and validate session token
    let token = match extract_token_from_headers(&headers) {
        Ok(token) => token,
        Err(e) => return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: e }))),
    };

    // Validate session and get user
    let user = match db.validate_session(&token).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid session token".to_string(),
                }),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Session validation failed".to_string(),
                }),
            ));
        }
    };

    // Get yo messages
    match db.get_yo_messages(&user.id).await {
        Ok(messages) => {
            let message_infos: Vec<YoMessageInfo> = messages
                .into_iter()
                .map(|msg| YoMessageInfo {
                    id: msg.id,
                    from: msg.from,
                    to: msg.to,
                    sent_at: msg.sent_at,
                })
                .collect();

            Ok(Json(YoMessagesResponse {
                messages: message_infos,
            }))
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to retrieve yo messages".to_string(),
            }),
        )),
    }
}

// Admin Handler functions
#[axum::debug_handler]
pub async fn admin_create_user(
    State(db): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let password = "password123";

    match db.create_user(&username, password).await {
        Ok(_) => {
            // Redirect back to admin page
            axum::response::Redirect::to("/admin")
        }
        Err(_) => {
            // In case of error, still redirect back
            axum::response::Redirect::to("/admin")
        }
    }
}

#[axum::debug_handler]
pub async fn admin_create_connection(
    State(db): State<AppState>,
    Path((from_username, to_username)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut error_message = None;

    // Get the user ID for the "from" user
    let from_user = db
        .get_user_by_username(&from_username)
        .await
        .unwrap_or_default();

    if let Some(user) = from_user {
        // Create connection request
        match db.create_connection(&user.id, &to_username).await {
            Ok(_) => {
                println!(
                    "Successfully created connection request: {} → {}",
                    from_username, to_username
                );
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("Connection already exists") {
                    println!(
                        "Connection already exists between {} and {}",
                        from_username, to_username
                    );
                    error_message = Some(format!(
                        "Connection between {} and {} already exists",
                        from_username, to_username
                    ));
                } else if error_str.contains("User not found") {
                    println!("User {} not found", to_username);
                    error_message = Some(format!("User {} not found", to_username));
                } else {
                    println!(
                        "Error creating connection {} → {}: {}",
                        from_username, to_username, error_str
                    );
                    error_message = Some(format!("Error: {}", error_str));
                }
            }
        }
    } else {
        error_message = Some(format!("User {} not found", from_username));
    }

    // For now, just log the error and redirect. In a real app, you'd want to pass this to the template
    if let Some(msg) = error_message {
        println!("Admin connection creation error: {}", msg);
    }

    // Redirect back to admin page
    axum::response::Redirect::to("/admin")
}

#[axum::debug_handler]
pub async fn admin_accept_connection(
    State(db): State<AppState>,
    Path(connection_id): Path<String>,
) -> impl IntoResponse {
    // Get connection details to find the target user
    let connection_info = db
        .get_connection_info(&connection_id)
        .await
        .unwrap_or_default();

    if let Some(info) = connection_info {
        // Accept on behalf of the target user (the one who didn't initiate)
        let target_user_id = if info.initiated_by == info.user1_id {
            &info.user2_id
        } else {
            &info.user1_id
        };

        let _ = db.accept_connection(&connection_id, target_user_id).await;
    }

    // Redirect back to admin page
    axum::response::Redirect::to("/admin")
}

#[axum::debug_handler]
pub async fn admin_reject_connection(
    State(db): State<AppState>,
    Path(connection_id): Path<String>,
) -> impl IntoResponse {
    // Reject the connection
    let _ = db.reject_connection(&connection_id).await;

    // Redirect back to admin page
    axum::response::Redirect::to("/admin")
}

#[axum::debug_handler]
pub async fn admin_delete_user(
    State(db): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    // Delete the user and all related data
    let _ = db.delete_user(&user_id).await;

    // Redirect back to admin page
    axum::response::Redirect::to("/admin")
}

#[derive(OpenApi)]
#[openapi(
    paths(
        register_user,
        login_user,
        request_connection,
        get_connections,
        accept_connection,
        send_yo,
        get_yo_messages
    ),
    components(
        schemas(
            RegisterRequest,
            RegisterResponse,
            LoginRequest,
            LoginResponse,
            UserInfo,
            ErrorResponse,
            Connection,
            AddConnectionRequest,
            AddConnectionResponse,
            ConnectionsResponse,
            AcceptConnectionRequest,
            AcceptConnectionResponse,
            SendYoRequest,
            SendYoResponse,
            YoMessagesResponse,
            YoMessageInfo
        )
    ),
    tags(
        (name = "Authentication", description = "User registration and login endpoints"),
        (name = "Connections", description = "Friend/connection management endpoints"),
        (name = "Yo Messages", description = "Yo message sending and retrieval endpoints")
    ),
    info(
        title = "yo API",
        description = "A social connection API for managing user registrations, authentication, and friend connections",
        version = "0.1.0"
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

pub struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("Bearer")
                        .description(Some("Enter your session token"))
                        .build(),
                ),
            )
        }
    }
}

// App creation function
pub fn create_app(db: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/swagger-ui", get(swagger))
        .route("/admin/create-user/{username}", get(admin_create_user))
        .route(
            "/admin/create-connection/{from}/{to}",
            get(admin_create_connection),
        )
        .route(
            "/admin/accept-connection/{id}",
            get(admin_accept_connection),
        )
        .route(
            "/admin/reject-connection/{id}",
            get(admin_reject_connection),
        )
        .route("/admin/delete-user/{user_id}", get(admin_delete_user))
        .route("/api/register", post(register_user))
        .route("/api/login", post(login_user))
        .route("/api/connections/request", post(request_connection))
        .route("/api/connections", get(get_connections))
        .route("/api/connections/accept", post(accept_connection))
        .route("/api/yo", post(send_yo))
        .route("/api/yo", get(get_yo_messages))
        .route(
            "/api-docs/openapi.json",
            get(|| async { Json(ApiDoc::openapi()) }),
        )
        .with_state(db)
}
