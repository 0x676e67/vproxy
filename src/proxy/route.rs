/// Attempts to add a route to the given subnet on the loopback interface using
/// rtnetlink library.
///
/// This function checks if the current user has root privileges before
/// attempting to add the route. If the user does not have root privileges, the
/// function returns immediately.
///
/// # Arguments
///
/// * `subnet` - The subnet for which to add a route.
///
/// # Example
///
/// ```
/// let subnet = cidr::IpCidr::from_str("192.168.1.0/24").unwrap();
/// sysctl_route_add_cidr(&subnet).await.unwrap();
/// ```
pub async fn sysctl_route_add_cidr(subnet: &cidr::IpCidr) -> Result<(), std::io::Error> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Root privileges are required to add a route.",
        ));
    }

    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    let loopback_link_index = handle
        .link()
        .get()
        .set_name_filter("lo".to_string())
        .execute()
        .try_next()
        .await?
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Loopback interface not found",
        ))?
        .header
        .index;

    let mut req = handle.route().add();
    req.message_mut().header.destination_prefix_length = subnet.network_length();
    req.message_mut().header.destination_prefix = subnet.first_address().into();
    req.message_mut().header.table = rtnetlink::RouteTable::Main as u32;
    req.message_mut().header.protocol = rtnetlink::RouteProtocol::Boot as u8;
    req.message_mut().header.kind = rtnetlink::RouteKind::Unicast;
    req.message_mut().header.scope = rtnetlink::RouteScope::Universe;
    req.message_mut().header.link_index = Some(loopback_link_index);

    req.execute().await?;

    Ok(())
}

/// Tries to disable local binding for IPv6.
///
/// This function uses the `sysctl` command to disable local binding for IPv6.
/// It checks if the current user has root privileges before attempting to
/// change the setting. If the user does not have root privileges, the function
/// returns immediately. If the `sysctl` command fails, it prints an error
/// message to the console.
///
/// # Example
///
/// ```
/// sysctl_ipv6_no_local_bind();
/// ```
pub fn sysctl_ipv6_no_local_bind() {
    if !nix::unistd::Uid::effective().is_root() {
        return;
    }

    use sysctl::Sysctl;
    const CTLNAME: &str = "net.ipv6.ip_nonlocal_bind";

    let ctl = <sysctl::Ctl as Sysctl>::new(CTLNAME)
        .expect(&format!("could not get sysctl '{}'", CTLNAME));
    let _ = ctl.name().expect("could not get sysctl name");

    let old_value = ctl.value_string().expect("could not get sysctl value");

    let target_value = match old_value.as_ref() {
        "0" => "1",
        "1" | _ => &old_value,
    };

    ctl.set_value_string(target_value).unwrap_or_else(|e| {
        panic!(
            "could not set sysctl '{}' to '{}': {}",
            CTLNAME, target_value, e
        )
    });
}
