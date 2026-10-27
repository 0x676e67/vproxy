//! Offline browser-ACME launch plans; node mTLS keeps its signed local identity.
//!
//! No cache or CA operation belongs here. The generated process prepares that
//! mutable state only when an operator actually starts it. Manual plans retain
//! their original certificate checks and files instead of becoming ACME aliases.

use std::{fs, io, net::SocketAddr, path::Path};

use crate::manage::acme::Options;

use super::{
    AcmeLaunch, FORMAT, ProxyConfig, Report, Request, Response, Stage, canonical_directory,
    check_arguments, complete, equal_file, files, invalid, load, node_key_path, path_string, plan,
    prepared_request, state_directory,
};

/// Write a new private plan after validating local identity and pure ACME choices.
/// Only node public TLS files and the two checked scripts are copied. An error
/// before directory creation leaves no output; later errors retain partial files.
#[allow(clippy::too_many_arguments)]
pub(super) fn launch(
    prepared: &Path,
    response: &Path,
    output: &Path,
    binds: (SocketAddr, SocketAddr),
    executable: &Path,
    options: &Options,
    proxy_config: Option<&Path>,
    now: u64,
) -> io::Result<Report> {
    let output = files::output_path(output)?;
    let prepared = canonical_directory(prepared)?;
    let response = canonical_directory(response)?;
    let executable = fs::canonicalize(executable)?;
    let (request, request_hash) = prepared_request(&prepared, now)?;
    let (signed, response_hash) = load::<Response>(&response, Stage::Signed)?;
    verify_node_response(&prepared, &request, &request_hash, &signed, now)?;
    let acme = options
        .plan(&request.admin_origin)?
        .ok_or_else(|| invalid("an ACME launch plan requires explicit --acme"))?;
    let launch = AcmeLaunch {
        format_version: FORMAT,
        prepared,
        response,
        executable,
        request_sha256: request_hash,
        response_sha256: response_hash,
        admin_bind: binds.0,
        node_bind: binds.1,
        acme,
        proxy_config: proxy_config.map(ProxyConfig::capture).transpose()?,
    };
    let scripts = scripts(&output, &launch, &request)?;
    files::create_directory(&output)?;
    files::write(&output, "node.pem", signed.node_certificate_pem.as_bytes())?;
    files::write(
        &output,
        "node-ca.pem",
        request.authority.node_ca_pem.as_bytes(),
    )?;
    files::write(&output, "start.sh", scripts.0.as_bytes())?;
    files::write(&output, "start.ps1", scripts.1.as_bytes())?;
    complete(&output, Stage::AcmePlan, &launch, Some(request.node_id))
}

/// Recheck immutable plan/identity inputs without requiring an ACME leaf or cache.
/// The same read-only DB snapshot as manual setup includes committed WAL. A
/// rotated ACME certificate does not change this digest or the node identity.
pub(super) fn checked_launch(
    directory: &Path,
    now: u64,
) -> io::Result<(AcmeLaunch, Request, String)> {
    let (launch, hash) = load::<AcmeLaunch>(directory, Stage::AcmePlan)?;
    if launch.format_version != FORMAT {
        return Err(invalid("unsupported ACME launch plan format"));
    }
    let (request, request_hash) = prepared_request(&launch.prepared, now)?;
    let (response, response_hash) = load::<Response>(&launch.response, Stage::Signed)?;
    if request_hash != launch.request_sha256 || response_hash != launch.response_sha256 {
        return Err(invalid(
            "ACME launch plan inputs changed; create a new plan",
        ));
    }
    verify_node_response(&launch.prepared, &request, &request_hash, &response, now)?;
    equal_file(&directory.join("node.pem"), &response.node_certificate_pem)?;
    equal_file(
        &directory.join("node-ca.pem"),
        &request.authority.node_ca_pem,
    )?;
    let (posix, powershell) = scripts(directory, &launch, &request)?;
    equal_file(&directory.join("start.sh"), &posix)?;
    super::equal_powershell(&directory.join("start.ps1"), &powershell)?;
    Ok((launch, request, hash))
}

/// Preserve the response binding and all node certificate checks. The unused
/// manual browser leaf is deliberately not checked: its expiry cannot prevent
/// a browser-ACME restart. This does not renew or weaken node mTLS identities.
fn verify_node_response(
    directory: &Path,
    request: &Request,
    request_hash: &str,
    response: &Response,
    now: u64,
) -> io::Result<()> {
    if response.format_version != FORMAT || response.request_sha256 != request_hash {
        return Err(invalid(
            "signed response does not match this prepared request",
        ));
    }
    super::verify_node_response(directory, request, response, now)
}

fn scripts(
    directory: &Path,
    launch: &AcmeLaunch,
    request: &Request,
) -> io::Result<(String, String)> {
    let (check, serve) = arguments(directory, launch, request)?;
    plan::render(&launch.executable, &check, &serve)
}

/// Emit the same serve argv for scripts and a Linux user unit. Offline
/// validation rechecks any selected proxy JSON and its TLS references, but
/// starts no listener or CA request. Actual port availability and platform-
/// specific IPv6 dual-stack behavior are checked when serve binds.
pub(super) fn arguments(
    directory: &Path,
    launch: &AcmeLaunch,
    request: &Request,
) -> io::Result<(Vec<String>, Vec<String>)> {
    let acme = launch.acme.arguments(&request.admin_origin)?;
    if launch.admin_bind.port() == 0
        || launch.node_bind.port() == 0
        || overlaps(launch.admin_bind, launch.node_bind)
        || launch.acme.http_bind().is_some_and(|http| {
            overlaps(http, launch.admin_bind) || overlaps(http, launch.node_bind)
        })
    {
        return Err(invalid(
            "ACME launch listeners require non-zero, non-overlapping local binds",
        ));
    }
    let check = check_arguments(directory)?;
    let mut serve: Vec<String> = ["manage", "serve", "--data-dir"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    serve.push(path_string(&state_directory(&launch.prepared, request)?)?);
    for (flag, value) in [
        ("--bind", launch.admin_bind.to_string()),
        ("--public-origin", request.admin_origin.clone()),
        ("--node-bind", launch.node_bind.to_string()),
        ("--node-origin", request.node_origin.clone()),
        ("--node-ca", path_string(&directory.join("node-ca.pem"))?),
        ("--node-cert", path_string(&directory.join("node.pem"))?),
        (
            "--node-key",
            path_string(&node_key_path(&launch.prepared, request)?)?,
        ),
    ] {
        serve.extend([flag.to_owned(), value]);
    }
    serve.extend(acme);
    if let Some(proxy_config) = &launch.proxy_config {
        proxy_config.append_arguments(&mut serve)?;
    }
    Ok((check, serve))
}

/// Detect exact/mapped and same-family wildcard overlaps, not merely equal ports.
/// Separate specific addresses can use the same port. Cross-family wildcard
/// conflicts depend on the OS IPv6-only setting and remain a real-bind check.
/// Equal IPv6 addresses at different scopes are conservatively rejected here;
/// this offline rule is not a claim that the OS cannot bind both scopes.
fn overlaps(left: SocketAddr, right: SocketAddr) -> bool {
    if left.port() != right.port() {
        return false;
    }
    let left = left.ip().to_canonical();
    let right = right.ip().to_canonical();
    left == right
        || left.is_ipv4() == right.is_ipv4() && (left.is_unspecified() || right.is_unspecified())
}
