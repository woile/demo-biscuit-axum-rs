use axum::{
    body::Body,
    extract::{State, FromRef},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::{SignedCookieJar, cookie::Key};
use biscuit_auth::{Biscuit, KeyPair};
use models::User;
use std::{net::SocketAddr, sync::Arc, ops::Deref};
use thiserror::Error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
extern crate argon2;

#[derive(Debug, Error)]
enum AppError {
    #[error("Page `{0} not found")]
    NotFound(String),

    #[error("Unothorized")]
    AuthError(#[from] biscuit_auth::error::Token),
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
    key: Key
}

impl InnerState {
    fn new() -> Self {
        Self {
            root_keypair: KeyPair::new(),
            key: Key::generate()
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
    let app = app();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "biscuit_auth_rs=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);

    // run it with hyper on localhost:3000
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn app() -> Router<(), Body> {
    // let shared_state = SharedState::default();
    // let shared_state = Arc::new(InnerState::new());
    let shared_state = AppState::new();
    Router::new()
        .route("/health_check", get(health_check))
        .route("/login", post(login))
        .route("/register", post(register))
        .with_state(shared_state)
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, String::from("Ok").into_response())
}

async fn login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Json(user): Json<User>,
) -> Result<impl IntoResponse, AppError> {
    let root_keypair = &state.clone().root_keypair;
    let mut builder = Biscuit::builder(root_keypair);
    let res = builder.add_authority_fact(user.as_fact().as_str());
    println!("{res:?}");
    let res = builder.add_authority_check(r#"check if operation("read")"#);
    println!("{res:?}");

    let token = builder.build()?;
    let t64 = token.to_base64()?;
    println!("token: {}", t64);

    Ok((StatusCode::OK, t64).into_response())
}

async fn register(Json(new_user): Json<schemas::NewUser>) -> Result<impl IntoResponse, AppError> {
    println!("{new_user:?}");
    Ok((StatusCode::OK, "registered!").into_response())
}

async fn is_authenticated() -> Result<impl IntoResponse, AppError> {
    Ok((StatusCode::OK, "registered!").into_response())
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
mod session {

}
mod models {

    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    use biscuit_auth::KeyPair;
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
        pub fn as_fact(&self) -> String {
            format!(r#"user("{}")"#, self.username)
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
