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
use biscuit_auth::{macros::biscuit, Biscuit, KeyPair};
use models::{Existing, User};
use schemas::UserLogin;
use std::{collections::HashMap, net::SocketAddr, ops::Deref, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::models::AuthError;

extern crate argon2;

#[derive(Debug, Error)]
enum AppError {
    #[error("Authentication error: {source}")]
    AuthError {
        #[from]
        source: models::AuthError,
    },

    #[error("Internal Error")]
    InternalError(#[from] biscuit_auth::error::Token),

    #[error("Unauthorized")]
    Unauthorized,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", self);
        let body = self.to_string();
        let message = match self {
            AppError::AuthError { source } => (StatusCode::FORBIDDEN, Json(source.to_string())),
            AppError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(body)),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, Json(body)),
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
    // Here you'd validate the credentials
    // and you'd retrievehave a store that reads the user

    let authority = biscuit!(
        r#"
        // parameters can directly reference in-scope variables
        user({user_id});
        operation("write");
        operation("read");

        check if operation("write");
        check if operation("read");
        "# // operation = "read",
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

async fn register(
    State(state): State<AppState>,
    Json(new_user): Json<schemas::UserCreate>,
) -> Result<impl IntoResponse, AppError> {
    let user: User = new_user.try_into()?;
    let username = user.username.clone();
    tracing::debug!("converted to user {user:?}");
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
        let biscuit = Biscuit::from_base64(token.clone(), root_keypair.public())?;
        let mut authorizer = biscuit.authorizer()?;
        let res: Vec<(String,)> = authorizer
            .query("data($username) <- user($username)")
            .unwrap();

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
    pub struct UserCreate {
        #[validate(length(min = 2))]
        pub username: String,

        #[validate(length(min = 8))]
        pub password: String,
    }

    // Probably your UserCreate would be different, but as it
    // is now, we reuse it.
    pub type UserLogin = UserCreate;
}

mod models {

    use std::marker::PhantomData;

    use argon2::{
        password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    };
    use secrecy::{ExposeSecret, Secret};
    use serde::{Deserialize, Serialize};

    use crate::schemas::UserCreate;
    extern crate argon2;

    #[derive(Debug, Clone)]
    pub struct Existing;

    #[derive(Debug)]
    pub struct New;

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct User<State = New> {
        pub username: String,

        #[serde(skip_serializing)]
        pub password: Secret<String>,

        #[serde(skip_serializing)]
        state: PhantomData<State>,
    }

    impl User<New> {
        pub fn as_db_user(self) -> User<Existing> {
            User {
                username: self.username,
                password: self.password,
                state: PhantomData,
            }
        }
    }
    impl User<Existing> {
        pub fn get_id(&self) -> &str {
            &self.username
        }

        // Validate the password against an instance retrieved from the db
        // this method can be improved to only appear for db users using a
        // PanthomState: `User<State = Existing|New>`
        pub fn validate_password(&self, password_candidate: String) -> Result<(), AuthError> {
            let password_candidate = Secret::new(password_candidate);

            // TODO: Run inside a `spawn_blocking`
            verify_password_hash(&self.password, password_candidate)
        }
    }

    impl TryFrom<UserCreate> for User<New> {
        type Error = AuthError;

        fn try_from(value: UserCreate) -> Result<Self, Self::Error> {
            let password = Secret::new(value.password);
            tracing::debug!("pass: {:?}", password);
            let password = compute_password_hash(password)?;

            Ok(Self {
                username: value.username,
                password: password,
                state: PhantomData,
            })
        }
    }

    #[derive(thiserror::Error, Debug)]
    pub enum AuthError {
        #[error("Invalid credentials.")]
        InvalidCredentials,

        #[error("Unexpected error.")]
        UnexpectedError(#[from] argon2::password_hash::Error),
    }

    pub fn compute_password_hash(password: Secret<String>) -> Result<Secret<String>, AuthError> {
        let salt = SaltString::generate(&mut rand::thread_rng());
        let password_hash = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(15000, 2, 1, None).expect("Invalid params, should not fail"),
        )
        .hash_password(password.expose_secret().as_bytes(), &salt)?
        .to_string();
        Ok(Secret::new(password_hash))
    }

    pub fn verify_password_hash(
        expected_password_hash: &Secret<String>,
        password_candidate: Secret<String>,
    ) -> Result<(), AuthError> {
        let expected_password_hash = PasswordHash::new(expected_password_hash.expose_secret())?;

        Argon2::default()
            .verify_password(
                password_candidate.expose_secret().as_bytes(),
                &expected_password_hash,
            )
            .map_err(|_e| AuthError::InvalidCredentials)
    }
}
