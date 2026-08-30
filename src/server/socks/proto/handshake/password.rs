use bytes::Bytes;

pub const SUBNEGOTIATION_VERSION: u8 = 0x01;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Status {
    Succeeded = 0x00,
    Failed = 0xff,
}

impl From<Status> for u8 {
    #[inline]
    fn from(value: Status) -> Self {
        value as u8
    }
}

/// Required for a username + password authentication.
#[derive(Default, Debug, Eq, PartialEq, Clone, Hash)]
pub struct UsernamePassword {
    pub username: Bytes,
    pub password: Bytes,
}

impl std::fmt::Display for UsernamePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
        match (self.username.is_empty(), self.password.is_empty()) {
            (true, true) => write!(f, ""),
            (true, false) => write!(
                f,
                ":{}",
                percent_encode(self.password.as_ref(), NON_ALPHANUMERIC)
            ),
            (false, true) => write!(
                f,
                "{}",
                percent_encode(self.username.as_ref(), NON_ALPHANUMERIC)
            ),
            (false, false) => {
                let username = percent_encode(self.username.as_ref(), NON_ALPHANUMERIC);
                let password = percent_encode(self.password.as_ref(), NON_ALPHANUMERIC);
                write!(f, "{username}:{password}")
            }
        }
    }
}

impl UsernamePassword {
    /// Constructs credentials from their RFC 1929 octet sequences.
    ///
    /// RFC 1929 defines UNAME and PASSWD as length-delimited octets rather than
    /// text with a required character encoding.
    /// https://www.rfc-editor.org/rfc/rfc1929.html#section-2
    pub fn new<U, P>(username: U, password: P) -> Self
    where
        U: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        Self {
            username: Bytes::copy_from_slice(username.as_ref()),
            password: Bytes::copy_from_slice(password.as_ref()),
        }
    }

    #[inline]
    pub(in crate::server::socks::proto) fn from_bytes(username: Bytes, password: Bytes) -> Self {
        Self { username, password }
    }
}
