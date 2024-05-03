/// A proxy authentication method.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Method {
    /// No authentication required.
    NoAuth              = 0x00,
    /// GSS API.
    GssApi              = 0x01,
    /// A username + password authentication.
    Password            = 0x02,
    /// IANA reserved 0x03..=0x7f.
    IanaReserved(u8),
    /// A private authentication method 0x80..=0xfe.
    Private(u8),
    /// X'FF' NO ACCEPTABLE METHODS
    NoAcceptableMethods = 0xff,
}

impl From<u8> for Method {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Method::NoAuth,
            0x01 => Method::GssApi,
            0x02 => Method::Password,
            0x03..=0x7f => Method::IanaReserved(value),
            0x80..=0xfe => Method::Private(value),
            0xff => Method::NoAcceptableMethods,
        }
    }
}

impl From<Method> for u8 {
    fn from(value: Method) -> Self {
        From::<&Method>::from(&value)
    }
}

impl From<&Method> for u8 {
    fn from(value: &Method) -> Self {
        match value {
            Method::NoAuth => 0x00,
            Method::GssApi => 0x01,
            Method::Password => 0x02,
            Method::IanaReserved(value) => *value,
            Method::Private(value) => *value,
            Method::NoAcceptableMethods => 0xff,
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Method::NoAuth => write!(f, "NoAuth"),
            Method::GssApi => write!(f, "GssApi"),
            Method::Password => write!(f, "UserPass"),
            Method::IanaReserved(value) => write!(f, "IanaReserved({0:#x})", value),
            Method::Private(value) => write!(f, "Private({0:#x})", value),
            Method::NoAcceptableMethods => write!(f, "NoAcceptableMethods"),
        }
    }
}
