use futures::TryStreamExt;
use netlink_packet_route::{
    route::{RouteAddress, RouteAttribute, RouteProtocol, RouteScope, RouteType},
    AddressFamily,
};
use rtnetlink::{new_connection, Error, Handle, IpVersion};

/// Attempts to add a route to the given subnet on the loopback interface.
///
/// This function uses the `ip` command to add a route to the loopback
/// interface. It checks if the current user has root privileges before
/// attempting to add the route. If the user does not have root privileges, the
/// function returns immediately. If the `ip` command fails, it prints an error
/// message to the console.
///
/// # Arguments
///
/// * `subnet` - The subnet for which to add a route.
///
/// # Example
///
/// ```
/// let subnet = cidr::IpCidr::from_str("192.168.1.0/24").unwrap();
/// sysctl_route_add_cidr(&subnet);
/// ```
pub async fn sysctl_route_add_cidr(subnet: &cidr::IpCidr) {
    if !nix::unistd::Uid::effective().is_root() {
        return;
    }

    let (connection, handle, _) = new_connection().unwrap();

    tokio::spawn(connection);

    if let Err(e) = add_route(handle.clone(), subnet).await {
        eprintln!("{e}");
    }
}

async fn add_route(handle: Handle, cidr: &cidr::IpCidr) -> Result<(), Error> {
    let route = handle.route();
    let iface_idx = handle
        .link()
        .get()
        .match_name("lo".to_owned())
        .execute()
        .try_next()
        .await?
        .unwrap()
        .header
        .index;

    // Check if the route already exists
    let route_check = |ip_version: IpVersion,
                       address_family: AddressFamily,
                       destination_prefix_length: u8,
                       route_address: RouteAddress| async move {
        let mut routes = handle.route().get(ip_version).execute();
        while let Some(route) = routes.try_next().await? {
            let header = route.header;
            if header.address_family == address_family
                && header.destination_prefix_length == destination_prefix_length
            {
                for attr in route.attributes.iter() {
                    if let RouteAttribute::Destination(dest) = attr {
                        if dest == &route_address {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    };

    // Add a route to the loopback interface.
    match cidr {
        cidr::IpCidr::V4(v4) => {
            if route_check(
                IpVersion::V4,
                AddressFamily::Inet,
                v4.network_length(),
                RouteAddress::Inet(v4.first_address()),
            )
            .await?
            {
                return Ok(());
            }
            route
                .add()
                .v4()
                .destination_prefix(v4.first_address(), v4.network_length())
                .kind(RouteType::Local)
                .protocol(RouteProtocol::Boot)
                .scope(RouteScope::Universe)
                .output_interface(iface_idx)
                .priority(1024)
                .execute()
                .await?
        }
        cidr::IpCidr::V6(v6) => {
            if route_check(
                IpVersion::V6,
                AddressFamily::Inet6,
                v6.network_length(),
                RouteAddress::Inet6(v6.first_address()),
            )
            .await?
            {
                return Ok(());
            }
            route
                .add()
                .v6()
                .destination_prefix(v6.first_address(), v6.network_length())
                .kind(RouteType::Local)
                .protocol(RouteProtocol::Boot)
                .scope(RouteScope::Universe)
                .output_interface(iface_idx)
                .priority(1024)
                .execute()
                .await?
        }
    }

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
