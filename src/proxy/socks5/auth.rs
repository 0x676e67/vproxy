use crate::proxy::auth::Authentication;

/// Basic user/pass auth method provided.
pub struct SimpleUserPassword {
    pub username: String,
    pub password: String,
}

/// The struct returned when the user has successfully authenticated
pub struct AuthSucceeded {
    pub username: String,
}

/// This is an example to auth via simple credentials.
/// If the auth succeed, we return the username authenticated with, for further
/// uses.
impl Authentication for SimpleUserPassword {
    type Item = AuthSucceeded;

    async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item> {
        if let Some((username, password)) = credentials {
            // Client has supplied credentials
            if username == self.username && password == self.password {
                // Some() will allow the authentication and the credentials
                // will be forwarded to the socket
                Some(AuthSucceeded { username })
            } else {
                // Credentials incorrect, we deny the auth
                None
            }
        } else {
            // The client hasn't supplied any credentials, which only happens
            // when `Config::allow_no_auth()` is set as `true`
            None
        }
    }
}

/// This will simply return Option::None, which denies the authentication
#[derive(Copy, Clone, Default)]
pub struct DenyAuthentication {}

impl Authentication for DenyAuthentication {
    type Item = ();

    async fn authenticate(&self, _credentials: Option<(String, String)>) -> Option<Self::Item> {
        None
    }
}

/// While this one will always allow the user in.
#[derive(Copy, Clone, Default)]
pub struct AcceptAuthentication {}

impl Authentication for AcceptAuthentication {
    type Item = ();

    async fn authenticate(&self, _credentials: Option<(String, String)>) -> Option<Self::Item> {
        Some(())
    }
}
