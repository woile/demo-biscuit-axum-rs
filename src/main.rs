use axum::{
    body::Body,
    extract::{FromRef, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::{
    cookie::{Cookie, Key},
    SignedCookieJar,
};
use biscuit_auth::{
    macros::{authorizer, biscuit},
    Biscuit, KeyPair,
};

use demo_biscuit_axum_rs::models::{AuthError, Existing, User};
use demo_biscuit_axum_rs::schemas::{UserCreate, UserLogin};
use std::{collections::HashMap, net::SocketAddr, ops::Deref, sync::Arc, time::{SystemTime, Duration}};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use validator::Validate;

extern crate argon2;

#[derive(Debug, Error)]
enum AppError {
    #[error("Authentication error: {source}")]
    AuthError {
        #[from]
        source: AuthError,
    },

    #[error("Invalid input: {source}")]
    ValidationError {
        #[from]
        source: validator::ValidationErrors,
    },

    #[error("Unauthorized")]
    TokenError(#[from] biscuit_auth::error::Token),

    #[error("Unauthorized")]
    Unauthorized,
}


impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", self);
        let body = self.to_string();
        let message = match self {
            AppError::AuthError { source } => (StatusCode::FORBIDDEN, Json(source.to_string())),
            AppError::TokenError(err) => match err.to_owned() {
                biscuit_auth::error::Token::FailedLogic(_) => {
                    (StatusCode::UNAUTHORIZED, Json(body))
                }
                biscuit_auth::error::Token::Format(_) => {
                    (StatusCode::FORBIDDEN, Json(String::from("Forbidden")))
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(String::from("Server Error")),
                ),
            },
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, Json(body)),
            AppError::ValidationError { source } => {
                (StatusCode::BAD_REQUEST, Json(source.to_string()))
            }
        };
        message.into_response()
    }
}

#[derive(Clone, FromRef)]
struct AppState(Arc<InnerState>);

impl AppState {
    fn new() -> Self {
        Self(Arc::new(InnerState::new()))
    }
}
impl Deref for AppState {
    type Target = InnerState;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

// Implemented as an in-memory hashmap protected with a RwLock
// but you should take care of persisting using
// something like `sqlx`.
// TODO: Should we use tokio::RwLock or std::RwLock?
type Database = RwLock<HashMap<String, User<Existing>>>;

struct InnerState {
    root_keypair: KeyPair,
    key: Key,
    database: Database,
}

impl InnerState {
    fn new() -> Self {
        Self {
            // WARN: KeyPair should be persisted, in this case
            // every time the server starts a new pair is created
            root_keypair: KeyPair::new(),
            key: Key::generate(),
            database: Database::default(),
        }
    }
}
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.0.key.clone()
    }
}

/// Endpoint used to verify that the app is up and running
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, String::from("Ok").into_response())
}

/// Reads a user from the store, and checks hashed password
/// If the user is valid, a biscuit token is created with a few
/// facts loaded.
async fn login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Json(user): Json<UserLogin>,
) -> Result<impl IntoResponse, AppError> {
    let username = &user.username;
    let state = &state.clone();
    let ackquired_db = state.database.read().await;
    let db_user = ackquired_db
        .get(username)
        .ok_or(AuthError::InvalidCredentials)?;

    db_user.validate_password(user.password)?;

    let user_id = db_user.get_id();
    let root_keypair = &state.root_keypair;

    // facts carried by the token
    let authority = biscuit!(
        r#"
        user({user_id});
        right("write");
        right("read");

        check if time($time), $time <= {expiration};
        "#,
        expiration = SystemTime::now() + Duration::from_secs(60),
    );

    let token = authority.build(&root_keypair)?;
    let session_id = token.to_base64()?;

    // WARN: This is just for demonstration purposes, but it should not be logged
    tracing::debug!("token: {}", session_id);

    Ok((
        jar.add(Cookie::new("session_id", session_id)),
        Redirect::to("/health_check"),
    ))
}

/// Add a new user to the store.
/// NEXT: We could add email and also validate
async fn register(
    State(state): State<AppState>,
    Json(new_user): Json<UserCreate>,
) -> Result<impl IntoResponse, AppError> {
    new_user.validate()?;
    let user: User = new_user.try_into()?;
    let username = user.username.clone();
    let created_user = user.as_db_user();
    state
        .database
        .write()
        .await
        .insert(username, created_user.clone());
    Ok((StatusCode::OK, Json(created_user)).into_response())
}

async fn is_authenticated(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<impl IntoResponse, AppError> {
    let session = jar.get("session_id");
    if let Some(session_id) = session {
        let token = session_id.value().to_owned();
        let root_keypair = &state.clone().root_keypair;
        let token = Biscuit::from_base64(token, root_keypair.public())?;
        let mut authorizer = authorizer!(
            r#"
            resource("is_authenticated");
            operation("read");

            allow if user($username), right("read"), right("write"), operation($o);
            "#
        );
        authorizer.set_time();
        authorizer.add_token(&token)?;
        tracing::debug!("{}", authorizer.dump_code());
        authorizer.authorize()?;

        // Extract the user for further usage.
        // It could be fetched from db, or use the id to retrive an item, etc.
        let res: Vec<(String,)> = authorizer
            .query("data($username) <- user($username)")
            .unwrap();

        if let Some((username,)) = res.first() {
            return Ok((StatusCode::OK, username.clone()).into_response());
        }
    }
    Err(AppError::Unauthorized)
}

fn auth_routes() -> Router<(), Body> {
    // let shared_state = SharedState::default();
    // let shared_state = Arc::new(InnerState::new());
    let shared_state = AppState::new();
    let pubkey = hex::encode(shared_state.0.root_keypair.public().to_bytes());
    tracing::debug!("hex public key: {pubkey}");

    Router::new()
        .route("/health_check", get(health_check))
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/is_auth", get(is_authenticated))
        .with_state(shared_state)
}

#[tokio::main]
async fn main() {
    // build our application with a single route

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "demo_biscuit_axum_rs=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let routes = auth_routes();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);

    // run on localhost:3000
    axum::Server::bind(&addr)
        .serve(routes.into_make_service())
        .await
        .unwrap();
}
