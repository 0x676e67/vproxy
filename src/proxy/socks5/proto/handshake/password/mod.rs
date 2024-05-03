mod request;
mod response;

pub use self::{
    request::Request,
    response::{Response, Status},
};
use serde::{Deserialize, Serialize};

pub const SUBNEGOTIATION_VERSION: u8 = 0x01;

/// Required for a username + password authentication.
#[derive(Default, Debug, Eq, PartialEq, Clone, Hash, Deserialize, Serialize)]
pub struct UserKey {
    pub username: String,
    pub password: String,
}

impl std::fmt::Display for UserKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
        match (self.username.is_empty(), self.password.is_empty()) {
            (true, true) => write!(f, ""),
            (true, false) => write!(
                f,
                ":{}",
                percent_encode(self.password.as_bytes(), NON_ALPHANUMERIC)
            ),
            (false, true) => write!(
                f,
                "{}",
                percent_encode(self.username.as_bytes(), NON_ALPHANUMERIC)
            ),
            (false, false) => {
                let username =
                    percent_encode(self.username.as_bytes(), NON_ALPHANUMERIC).to_string();
                let password =
                    percent_encode(self.password.as_bytes(), NON_ALPHANUMERIC).to_string();
                write!(f, "{}:{}", username, password)
            }
        }
    }
}

impl UserKey {
    /// Constructs `UserKey` with the specified username and a password.
    pub fn new<U, P>(username: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn username_arr(&self) -> Vec<u8> {
        self.username.as_bytes().to_vec()
    }

    pub fn password_arr(&self) -> Vec<u8> {
        self.password.as_bytes().to_vec()
    }
}

#[test]
fn test_user_key() {
    let user_key = UserKey::new("username", "pass@word");
    assert_eq!(user_key.to_string(), "username:pass%40word");
    let user_key = UserKey::new("username", "");
    assert_eq!(user_key.to_string(), "username");
    let user_key = UserKey::new("", "password");
    assert_eq!(user_key.to_string(), ":password");
    let user_key = UserKey::new("", "");
    assert_eq!(user_key.to_string(), "");
}
