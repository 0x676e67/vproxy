/// Load Balancing IP Manager
use anyhow::Result;
use headers::{authorization::Basic, Authorization};
use http::{uri::Scheme, Uri};

use std::{
    fs::File,
    io::BufRead,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use url::Url;

use crate::proxy::socks5::proto::UsernamePassword;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct InnerProxy {
    pub uri: Uri,
    pub scheme: InnerScheme,
    pub auth: InnerAuth,
}

impl InnerProxy {
    pub fn host(&self) -> &str {
        self.uri.host().unwrap_or("localhost")
    }

    pub fn port(&self) -> u16 {
        self.uri
            .port_u16()
            .unwrap_or(if self.uri.scheme() == Some(&Scheme::HTTPS) {
                443
            } else {
                80
            })
    }
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum InnerScheme {
    HTTP,
    SOCKS5,
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum InnerAuth {
    NoAuth,
    Password { username: String, password: String },
}

impl Into<Option<UsernamePassword>> for InnerAuth {
    fn into(self) -> Option<UsernamePassword> {
        match self {
            InnerAuth::NoAuth => None,
            InnerAuth::Password { username, password } => {
                Some(UsernamePassword::new(username, password))
            }
        }
    }
}

impl Into<Option<Authorization<Basic>>> for InnerAuth {
    fn into(self) -> Option<Authorization<Basic>> {
        match self {
            InnerAuth::NoAuth => None,
            InnerAuth::Password { username, password } => {
                Some(Authorization::basic(&username, &password))
            }
        }
    }
}

pub struct ProxyLoadBalancer {
    proxies: Vec<InnerProxy>,
    load: AtomicUsize,
}

impl ProxyLoadBalancer {
    pub fn new(path: PathBuf) -> Result<Self> {
        let mut proxies = vec![];

        let file = File::open(path)?;
        let reader = std::io::BufReader::new(file);
        for url in reader.lines() {
            let mut url = url?.parse::<Url>()?;

            tracing::info!("Add proxy {} to pool", url);

            let scheme = match url.scheme() {
                "http" => InnerScheme::HTTP,
                "socks5" => {
                    // fix Service call
                    url = url.as_str().replace("socks5", "http").parse()?;
                    InnerScheme::SOCKS5
                }
                _ => {
                    anyhow::bail!("Unsupport {} proxy", url.scheme());
                }
            };

            let auth_username = url.username();
            let auth_password = url.password();

            let auth = if auth_username.is_empty() || auth_password.is_none() {
                InnerAuth::NoAuth
            } else {
                InnerAuth::Password {
                    username: auth_username.to_owned(),
                    password: auth_password.map(ToOwned::to_owned).unwrap(),
                }
            };

            let _ = url.set_username("");
            let _ = url.set_password(None);

            let proxy = InnerProxy {
                scheme,
                auth,
                uri: url.as_str().parse()?,
            };

            proxies.push(proxy)
        }

        if proxies.is_empty() {
            anyhow::bail!("Proxies cannot be empty")
        }

        Ok(Self {
            proxies,
            load: AtomicUsize::new(0),
        })
    }

    pub fn next_proxy(&self) -> InnerProxy {
        let index = round_robin_factor(self.proxies.len(), &self.load);
        self.proxies[index].clone()
    }
}

fn round_robin_factor(len: usize, counter: &AtomicUsize) -> usize {
    let mut old = counter.load(Ordering::Relaxed);
    let mut new;
    loop {
        new = (old + 1) % len;
        match counter.compare_exchange_weak(old, new, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => old = x,
        }
    }
    new
}
