mod request;
mod response;

pub use self::{
    request::Request,
    response::{Response, Status},
};

pub const SUBNEGOTIATION_VERSION: u8 = 0x01;

/// Required for a username + password authentication.
#[derive(Default, Debug, Eq, PartialEq, Clone, Hash)]
pub struct UsernamePassword {
    pub username: String,
    pub password: String,
}

impl std::fmt::Display for UsernamePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
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
                let username = percent_encode(self.username.as_bytes(), NON_ALPHANUMERIC);
                let password = percent_encode(self.password.as_bytes(), NON_ALPHANUMERIC);
                write!(f, "{username}:{password}")
            }
        }
    }
}

impl UsernamePassword {
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

    #[inline]
    pub fn username_bytes(&self) -> &[u8] {
        self.username.as_bytes()
    }

    #[inline]
    pub fn password_bytes(&self) -> &[u8] {
        self.password.as_bytes()
    }
}
