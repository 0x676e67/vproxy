use std::net::IpAddr;

pub trait Whitelist {
    fn contains(&self, ip: IpAddr) -> bool;
}
