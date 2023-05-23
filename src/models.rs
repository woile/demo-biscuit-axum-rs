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
