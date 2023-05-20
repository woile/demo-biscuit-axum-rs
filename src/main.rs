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
use biscuit_auth::{macros::{biscuit, biscuit_merge}, Biscuit, KeyPair};
use models::User;
use std::{net::SocketAddr, ops::Deref, sync::Arc};
use thiserror::Error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
extern crate argon2;

#[derive(Debug, Error)]
enum AppError {
    #[error("Page `{0} not found")]
    NotFound(String),

    #[error("Error")]
    AuthError(#[from] biscuit_auth::error::Token),

    #[error("Unauthorized")]
    Unauthorized,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = self.to_string();

        (StatusCode::FORBIDDEN, body).into_response()
    }
}

#[derive(Clone)]
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
struct InnerState {
    root_keypair: KeyPair,
    key: Key,
}

impl InnerState {
    fn new() -> Self {
        Self {
            root_keypair: KeyPair::new(),
            key: Key::generate(),
        }
    }
}
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.0.key.clone()
    }
}

#[tokio::main]
async fn main() {
    // build our application with a single route

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "biscuit_auth_rs=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = app();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);

    // run on localhost:3000
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn app() -> Router<(), Body> {
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

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, String::from("Ok").into_response())
}

/// This login does not login against a store
/// it just creates a token from the given user as json.
/// Reading the user from a store is out of the scope of
/// this demo.
async fn login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Json(user): Json<User>,
) -> Result<impl IntoResponse, AppError> {
    let root_keypair = &state.clone().root_keypair;
    // Here you'd validate the credentials
    // and you'd retrievehave a store that reads the user
    let user_id = user.get_id();

    let authority = biscuit!(
        r#"
        // parameters can directly reference in-scope variables
        user({user_id});
        operation("write");
        // parameters can be manually supplied as well
        // right({user_id}, "file1", {operation});
        // right({user_id}, "file1", {operation});
        check if operation("write");
        "#
        // operation = "read",
    );

    let token = authority.build(&root_keypair)?;
    let session_id = token.to_base64()?;
    println!("token: {}", session_id);

    // Ok((StatusCode::OK).into_response())
    Ok((
        jar.add(Cookie::new("session_id", session_id)),
        Redirect::to("/health_check"),
    ))
}

async fn register(Json(new_user): Json<schemas::NewUser>) -> Result<impl IntoResponse, AppError> {
    println!("{new_user:?}");
    Ok((StatusCode::OK, "registered!").into_response())
}

async fn is_authenticated(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<impl IntoResponse, AppError> {
    let session = jar.get("session_id");
    if let Some(session_id) = session {
        println!("{session_id:?}");
        let token = session_id.value().to_owned();
        let root_keypair = &state.clone().root_keypair;
        let biscuit = Biscuit::from_base64(token.clone(), root_keypair.public())?;
        let mut authorizer = biscuit.authorizer()?;
        let res: Vec<(String,)> = authorizer
            .query("data($username) <- user($username)")
            .unwrap();
        println!("{res:?}");
        if let Some((username,)) = res.first() {
            return Ok((StatusCode::OK, username.clone()).into_response());
        }
    }
    Err(AppError::Unauthorized)
}

mod schemas {
    use serde::Deserialize;
    use validator::Validate;

    #[derive(Deserialize, Validate, Debug)]
    pub struct NewUser {
        #[validate(email)]
        pub email: String,
    }
}
mod session {}
mod models {

    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    use secrecy::{ExposeSecret, Secret};
    use serde::Deserialize;
    extern crate argon2;

    #[derive(Debug, Deserialize)]
    pub struct User {
        pub username: String,
        pub password: Secret<String>,
    }

    impl User {
        pub fn new(username: String, password: String) -> Self {
            Self {
                username,
                password: Secret::new(password),
            }
        }

        pub fn get_id(&self) -> &str {
            &self.username
        }
    }

    #[derive(thiserror::Error, Debug)]
    pub enum AuthError {
        #[error("Invalid credentials.")]
        InvalidCredentials,

        #[error("Unexpected error.")]
        UnexpectedError(#[from] argon2::password_hash::Error),
    }

    // fn validate_credentials(keypair: KeyPair) -> Result<User, Error> {

    //     todo!("not implemented")

    // }

    fn verify_password_hash(
        expected_password_hash: Secret<String>,
        password_candidate: Secret<String>,
    ) -> Result<(), AuthError> {
        let expected_password_hash = PasswordHash::new(expected_password_hash.expose_secret())?;

        Argon2::default()
            .verify_password(
                password_candidate.expose_secret().as_bytes(),
                &expected_password_hash,
            )
            .map_err(|e| AuthError::InvalidCredentials)
    }
}
