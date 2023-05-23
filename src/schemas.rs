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
