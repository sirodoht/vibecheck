use askama::Template;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc};

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

// User-related structures for API
#[derive(sqlx::FromRow, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip)] // Never serialize password hash
    pub password_hash: String,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
    pub user_id: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<UserInfo>,
    pub token: Option<String>,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct Connection {
    pub id: String,
    pub user_id: String,
    pub friend_id: String,
    pub friend_username: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct AddConnectionRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct AddConnectionResponse {
    pub success: bool,
    pub message: String,
    pub connection_id: Option<String>,
}

#[derive(Serialize)]
pub struct ConnectionsResponse {
    pub success: bool,
    pub connections: Vec<Connection>,
}

// Web Handler functions
async fn index(State(db): State<AppState>) -> impl IntoResponse {
    let users = db.get_all_users().await.unwrap_or_default();
    let total_users = users.len() as i64;
    let template = IndexTemplate { users, total_users };
    Html(template.render().unwrap())
}

// API Handler functions
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
            message: format!("Successfully connected to {}", request.username),
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

#[tokio::main]
async fn main() {
    // Check command line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("vibecheckapi - User Registration API");
        println!();
        println!("Usage:");
        println!(
            "  {} --serve         Start the user registration API server",
            args[0]
        );
        println!();
        return;
    }

    if args.len() > 1 && args[1] == "--serve" {
        // Initialize database
        let database_url = "sqlite:./vibecheckapi.db";
        let db = Database::new(database_url)
            .await
            .expect("Failed to connect to database");

        // Run migrations
        if let Err(e) = db.run_migrations().await {
            eprintln!("Failed to run migrations: {}", e);
            std::process::exit(1);
        }

        println!("Database ready for user registration API");

        let app_state = Arc::new(db);

        // Build the router
        let app = Router::new()
            .route("/", get(index))
            .route("/api/register", post(register_user))
            .route("/api/login", post(login_user))
            .route("/api/connections", post(add_connection))
            .route("/api/connections", get(get_connections))
            .with_state(app_state);

        // Start the server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
            .await
            .expect("Failed to bind to address");

        println!("Vibecheck API running on http://127.0.0.1:3000");

        axum::serve(listener, app)
            .await
            .expect("Failed to start server");
    } else {
        println!("Unknown argument. Use --serve to start the server.");
    }
}
