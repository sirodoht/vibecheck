use askama::Template;
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc};
use utoipa::{OpenApi, ToSchema};

mod database;
use database::Database;

// Application state
type AppState = Arc<Database>;

// Template structs
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    users: Vec<User>,
    total_users: i64,
}

#[derive(Template)]
#[template(path = "friends.html")]
struct FriendsTemplate {
    users_with_friends: Vec<UserWithFriends>,
    total_users_with_friends: i64,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminTemplate {
    users: Vec<User>,
    next_user_name: String,
    pending_connections: Vec<AdminConnection>,
    accepted_connections: Vec<AdminConnection>,
}

#[derive(Template)]
#[template(path = "swagger.html")]
struct SwaggerTemplate;

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

#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
    /// Whether the registration was successful
    pub success: bool,
    /// Human-readable message about the registration result
    pub message: String,
    /// The ID of the newly created user (if successful)
    pub user_id: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    /// The username to authenticate
    pub username: String,
    /// The password to authenticate
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    /// Whether the login was successful
    pub success: bool,
    /// Human-readable message about the login result
    pub message: String,
    /// User information (if login successful)
    pub user: Option<UserInfo>,
    /// Authentication token for subsequent requests (if login successful)
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

#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Error message describing what went wrong
    pub error: String,
}

#[derive(sqlx::FromRow, Serialize, ToSchema)]
pub struct Connection {
    /// Unique connection ID
    pub id: String,
    /// ID of first user in the connection
    pub user1_id: String,
    /// ID of second user in the connection
    pub user2_id: String,
    /// Username of the other user (not the requesting user)
    pub other_username: String,
    /// Status of the connection (pending or accepted)
    pub status: String,
    /// User ID who initiated the connection request
    pub initiated_by: String,
    /// Timestamp when the connection was created
    pub created_at: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AddConnectionRequest {
    /// Username of the user to send a connection request to
    pub username: String,
}

#[derive(Serialize, ToSchema)]
pub struct AddConnectionResponse {
    /// Whether the connection request was successful
    pub success: bool,
    /// Human-readable message about the request result
    pub message: String,
    /// ID of the newly created connection (if successful)
    pub connection_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ConnectionsResponse {
    /// Whether the request was successful
    pub success: bool,
    /// List of user connections
    pub connections: Vec<Connection>,
}

#[derive(Deserialize, ToSchema)]
pub struct AcceptConnectionRequest {
    /// ID of the connection to accept
    pub connection_id: String,
}

#[derive(Serialize, ToSchema)]
pub struct AcceptConnectionResponse {
    /// Whether the acceptance was successful
    pub success: bool,
    /// Human-readable message about the acceptance result
    pub message: String,
}

// Admin-related structures (not needed anymore with path parameters)

// Web Handler functions
async fn index(State(db): State<AppState>) -> impl IntoResponse {
    let users = db.get_all_users().await.unwrap_or_default();
    let total_users = users.len() as i64;
    let template = IndexTemplate { users, total_users };
    Html(template.render().unwrap())
}

async fn friends(State(db): State<AppState>) -> impl IntoResponse {
    let users_with_friends = db.get_users_with_friends().await.unwrap_or_default();
    let total_users_with_friends = users_with_friends.len() as i64;
    let template = FriendsTemplate {
        users_with_friends,
        total_users_with_friends,
    };
    Html(template.render().unwrap())
}

async fn admin(State(db): State<AppState>) -> impl IntoResponse {
    let users = db.get_all_users().await.unwrap_or_default();

    // Calculate next user name
    let user_count = users.len();
    let next_user_name = format!("user{}", user_count + 1);

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

    let template = AdminTemplate {
        users,
        next_user_name,
        pending_connections,
        accepted_connections,
    };
    Html(template.render().unwrap())
}

async fn swagger() -> impl IntoResponse {
    let template = SwaggerTemplate;
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
async fn register_user(
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
        Ok(user_id) => Ok(Json(RegisterResponse {
            success: true,
            message: "User registered successfully".to_string(),
            user_id: Some(user_id),
        })),
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
async fn login_user(
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

    Ok(Json(LoginResponse {
        success: true,
        message: "Login successful".to_string(),
        user: Some(UserInfo {
            id: user.id,
            username: user.username,
            created_at: user.created_at,
        }),
        token: Some(token),
    }))
}

// Helper function to extract token from Authorization header
fn extract_token_from_headers(headers: &HeaderMap) -> Result<String, String> {
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
async fn add_connection(
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
        Ok(connection_id) => Ok(Json(AddConnectionResponse {
            success: true,
            message: format!(
                "Connection request sent to {}. Waiting for acceptance.",
                request.username
            ),
            connection_id: Some(connection_id),
        })),
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
async fn get_connections(
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
        Ok(connections) => Ok(Json(ConnectionsResponse {
            success: true,
            connections,
        })),
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
        (status = 404, description = "Connection not found", body = ErrorResponse),
        (status = 409, description = "Connection already accepted", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Connections",
    security(
        ("bearer_auth" = [])
    )
)]
async fn accept_connection(
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

    // Accept the connection
    match db.accept_connection(&request.connection_id, &user.id).await {
        Ok(()) => Ok(Json(AcceptConnectionResponse {
            success: true,
            message: "Connection accepted successfully".to_string(),
        })),
        Err(e) => {
            let error_msg = e.to_string();
            let status_code = if error_msg.contains("Connection not found") {
                StatusCode::NOT_FOUND
            } else if error_msg.contains("already accepted") {
                StatusCode::CONFLICT
            } else if error_msg.contains("not authorized")
                || error_msg.contains("cannot accept your own")
            {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            Err((status_code, Json(ErrorResponse { error: error_msg })))
        }
    }
}

// Admin Handler functions
#[axum::debug_handler]
async fn admin_create_user(
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
async fn admin_create_connection(
    State(db): State<AppState>,
    Path((from_username, to_username)): Path<(String, String)>,
) -> impl IntoResponse {
    // Get the user ID for the "from" user
    let from_user = db
        .get_user_by_username(&from_username)
        .await
        .unwrap_or_default();

    if let Some(user) = from_user {
        // Create connection request
        let _ = db.create_connection(&user.id, &to_username).await;
    }

    // Redirect back to admin page
    axum::response::Redirect::to("/admin")
}

#[axum::debug_handler]
async fn admin_accept_connection(
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
async fn admin_reject_connection(
    State(db): State<AppState>,
    Path(connection_id): Path<String>,
) -> impl IntoResponse {
    // Reject the connection
    let _ = db.reject_connection(&connection_id).await;

    // Redirect back to admin page
    axum::response::Redirect::to("/admin")
}

#[axum::debug_handler]
async fn admin_delete_user(
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
        add_connection,
        get_connections,
        accept_connection
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
            AcceptConnectionResponse
        )
    ),
    tags(
        (name = "Authentication", description = "User registration and login endpoints"),
        (name = "Connections", description = "Friend/connection management endpoints")
    ),
    info(
        title = "Vibecheck API",
        description = "A social connection API for managing user registrations, authentication, and friend connections",
        version = "0.1.0"
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

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

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    // Default values
    let mut port = 3000;
    let mut database_path = "./vibecheckapi.db".to_string();
    let mut serve = false;

    if args.len() == 1 {
        println!("vibecheckapi - User Registration API");
        println!();
        println!("Usage:");
        println!("  {} --serve [OPTIONS]", args[0]);
        println!();
        println!("Options:");
        println!("  --serve                    Start the user registration API server");
        println!("  --port <PORT>             Port to bind to (default: 3000)");
        println!("  --database <PATH>         Database file path (default: ./vibecheckapi.db)");
        println!();
        println!("Example:");
        println!(
            "  {} --serve --port 4000 --database /var/www/vibecheck/api/vibecheckapi.db",
            args[0]
        );
        println!();
        return;
    }

    // Parse arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--serve" => serve = true,
            "--port" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<u16>() {
                        Ok(p) => {
                            port = p;
                            i += 1; // Skip the next argument as it's the port value
                        }
                        Err(_) => {
                            eprintln!("Error: Invalid port number: {}", args[i + 1]);
                            std::process::exit(1);
                        }
                    }
                } else {
                    eprintln!("Error: --port requires a value");
                    std::process::exit(1);
                }
            }
            "--database" => {
                if i + 1 < args.len() {
                    database_path = args[i + 1].clone();
                    i += 1; // Skip the next argument as it's the database path
                } else {
                    eprintln!("Error: --database requires a value");
                    std::process::exit(1);
                }
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                println!("Use '{}' to see usage information.", args[0]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if !serve {
        println!("Error: --serve flag is required to start the server.");
        println!("Use '{}' to see usage information.", args[0]);
        std::process::exit(1);
    }

    // Initialize database
    let database_url = format!("sqlite:{}", database_path);
    let db = Database::new(&database_url)
        .await
        .expect("Failed to connect to database");

    // Run migrations
    if let Err(e) = db.run_migrations().await {
        eprintln!("Failed to run migrations: {}", e);
        std::process::exit(1);
    }

    println!(
        "Database ready for user registration API ({})",
        database_path
    );

    let app_state = Arc::new(db);

    // Build the router
    let app = Router::new()
        .route("/", get(index))
        .route("/friends", get(friends))
        .route("/admin", get(admin))
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
        .route("/api/connections", post(add_connection))
        .route("/api/connections", get(get_connections))
        .route("/api/connections/accept", post(accept_connection))
        .route(
            "/api-docs/openapi.json",
            get(|| async { Json(ApiDoc::openapi()) }),
        )
        .with_state(app_state);

    // Start the server
    let bind_address = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&bind_address)
        .await
        .expect("Failed to bind to address");

    println!("Vibecheck API running on http://{}", bind_address);

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}
