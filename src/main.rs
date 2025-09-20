use askama::Template;
use axum::{
    Router,
    extract::State,
    http::StatusCode,
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

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
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
