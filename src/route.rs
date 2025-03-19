use std::net::{Ipv4Addr, Ipv6Addr};

use cidr::IpCidr;
use futures::TryStreamExt;
use netlink_packet_route::{
    AddressFamily,
    route::{RouteAddress, RouteAttribute, RouteProtocol, RouteScope, RouteType},
};
use rtnetlink::{Error, Handle, RouteMessageBuilder, new_connection};
use sysctl::{Sysctl, SysctlError};

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
pub async fn sysctl_route_add_cidr(subnet: &IpCidr) {
    let (connection, handle, _) = new_connection().unwrap();

    tokio::spawn(connection);

    if let Err(e) = add_route(handle.clone(), subnet).await {
        tracing::trace!("Failed to apply route: {}", e);
    }
}

async fn add_route(handle: Handle, cidr: &IpCidr) -> Result<(), Error> {
    const LOCAL_TABLE_ID: u8 = 255;

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

    let route = handle.route();

    let (route_message, address_family, destination_prefix_length, route_address) = match cidr {
        IpCidr::V4(v4) => (
            RouteMessageBuilder::<Ipv4Addr>::new().build(),
            AddressFamily::Inet,
            v4.network_length(),
            RouteAddress::Inet(v4.first_address()),
        ),
        IpCidr::V6(v6) => (
            RouteMessageBuilder::<Ipv6Addr>::new().build(),
            AddressFamily::Inet6,
            v6.network_length(),
            RouteAddress::Inet6(v6.first_address()),
        ),
    };

    // Check if the route already exists
    let mut routes = route.get(route_message).execute();
    while let Some(route) = routes.try_next().await? {
        let header = route.header;
        tracing::trace!(
            "route attributes: {:?}\nroute header: {:?}",
            route.attributes,
            header
        );
        if header.address_family == address_family
            && header.destination_prefix_length == destination_prefix_length
            && header.table == LOCAL_TABLE_ID
        {
            for attr in route.attributes.iter() {
                if let RouteAttribute::Destination(dest) = attr {
                    if dest == &route_address {
                        tracing::info!("IP route {} already exists", cidr);
                        return Ok(());
                    }
                }
            }
        }
    }

    // Generate the route message
    let route_message = match cidr {
        IpCidr::V4(v4) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(v4.first_address(), v4.network_length())
            .kind(RouteType::Local)
            .protocol(RouteProtocol::Boot)
            .scope(RouteScope::Universe)
            .output_interface(iface_idx)
            .priority(1024)
            .table_id(LOCAL_TABLE_ID.into())
            .build(),
        IpCidr::V6(v6) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(v6.first_address(), v6.network_length())
            .kind(RouteType::Local)
            .protocol(RouteProtocol::Boot)
            .scope(RouteScope::Universe)
            .output_interface(iface_idx)
            .priority(1024)
            .table_id(LOCAL_TABLE_ID.into())
            .build(),
    };

    route.add(route_message).execute().await?;
    tracing::info!("Added IPv6 route {}", cidr);

    Ok(())
}

/// Tries to disable local binding for IPv6.
///
/// This function uses the `sysctl` command to disable local binding for IPv6.
/// It attempts to change the setting by calling the `execute_sysctl` function
/// with the appropriate parameters. If the `sysctl` command fails, it logs an
/// error message.
///
/// # Example
///
/// ```
/// sysctl_ipv6_no_local_bind();
/// ```
pub fn sysctl_ipv6_no_local_bind(subnet: &IpCidr) {
    if subnet.is_ipv6() {
        if let Err(err) = execute_sysctl("net.ipv6.ip_nonlocal_bind", "1") {
            tracing::trace!("Failed to execute sysctl: {}", err)
        }
    }
}

/// This function uses the `sysctl` command to enable IPv6 on all interfaces.
/// It attempts to change the setting by calling the `execute_sysctl` function
/// with the appropriate parameters. If the `sysctl` command fails, it logs an
/// error message.
///
/// # Example
///
/// ```
/// sysctl_ipv6_all_enable_ipv6();
/// ```
///
/// # Errors
///
/// If the `sysctl` command fails, this function logs an error message using
/// the `tracing` crate and returns an error.
///
/// # Safety
///
/// This function requires root privileges to execute the `sysctl` command.
/// Ensure that the program is running with the necessary permissions.
///
/// # See Also
///
/// * `execute_sysctl` - The function used to execute the `sysctl` command.
///
pub fn sysctl_ipv6_all_enable_ipv6(subnet: &IpCidr) {
    if subnet.is_ipv6() {
        if let Err(err) = execute_sysctl("net.ipv6.conf.all.disable_ipv6", "0") {
            tracing::trace!("Failed to execute sysctl: {}", err)
        }
    }
}

/// This function executes a `sysctl` command to modify a kernel parameter.
/// It creates a new `sysctl::Ctl` object with the specified command, retrieves
/// the current value of the parameter, logs the old value, and then sets the
/// parameter to the new value. If any step fails, it returns an error.
///
/// # Arguments
///
/// * `command` - The sysctl command to execute (e.g., "net.ipv6.ip_nonlocal_bind").
/// * `value` - The value to set for the specified sysctl command.
///
/// # Returns
///
/// * `Result<(), SysctlError>` - Returns `Ok(())` if the command succeeds,
///   otherwise returns a `SysctlError`.
///
/// # Example
///
/// ```
/// execute_sysctl("net.ipv6.ip_nonlocal_bind", "1")?;
/// ```
fn execute_sysctl(command: &str, value: &str) -> Result<(), SysctlError> {
    let ctl = <sysctl::Ctl as Sysctl>::new(command)?;
    assert_eq!(command, ctl.name()?);

    let old_value = ctl.value_string()?;
    tracing::trace!("Sysctl '{}' old value: {}", command, old_value);

    ctl.set_value_string(value).map(|_| {
        tracing::info!("Sysctl '{}' value: {}", command, value);
    })
}
