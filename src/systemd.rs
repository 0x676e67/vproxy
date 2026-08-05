//! systemd service installation and control for Linux.
//!
//! Vproxy stays in the foreground while systemd owns startup, restart, logging,
//! and process state.

use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    io,
    path::PathBuf,
    sync::mpsc::TryRecvError,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Args as _, Command as ClapCommand};
use sdjournal::{EntryOwned, LiveJournal, SubscriptionOptions};
use unitbus::{
    BlockingJobHandle, BlockingUnitBus, JobOutcome, ServiceType, ServiceUnitSpec, UnitStartMode,
    UnitStatus,
};

use crate::{BootArgs, Result, connect::Fallback};

const SERVICE_NAME: &str = concat!(env!("CARGO_PKG_NAME"), ".service");
const JOB_TIMEOUT: Duration = Duration::from_secs(30);
const RECENT_LOG_LIMIT: usize = 100;

#[derive(Clone, Copy)]
struct ServiceIdentity {
    uid: u32,
    gid: u32,
}

struct ServiceCommand {
    arguments: Vec<String>,
    working_directory: String,
    environment: BTreeMap<String, String>,
}

impl ServiceCommand {
    fn from_arguments(arguments: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let arguments = arguments.into_iter();
        let mut command = Vec::with_capacity(arguments.size_hint().0.saturating_add(1));
        command.push("run".to_owned());
        for argument in arguments {
            command.push(string_arg(argument, "server argument")?);
        }

        let mut working_directory = path_arg(env::current_dir()?, "working directory")?;
        escape_systemd_specifiers(&mut working_directory);

        Ok(Self {
            arguments: command,
            working_directory,
            environment: server_environment()?,
        })
    }
}

/// Installs, enables, and starts the service with the supplied server settings.
pub(crate) fn start(config: BootArgs, arguments: impl IntoIterator<Item = OsString>) -> Result<()> {
    let command = ServiceCommand::from_arguments(arguments)?;
    let bus = BlockingUnitBus::connect_system()?;
    install(&bus, &config, command)?;

    let status = wait_for_job(
        bus.units().start(SERVICE_NAME, UnitStartMode::Replace)?,
        "start",
    )?;
    print_action("started", &status);
    Ok(())
}

/// Updates the installed unit and restarts the service.
pub(crate) fn restart(
    config: BootArgs,
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<()> {
    let command = ServiceCommand::from_arguments(arguments)?;
    let bus = BlockingUnitBus::connect_system()?;
    install(&bus, &config, command)?;

    let status = wait_for_job(
        bus.units().restart(SERVICE_NAME, UnitStartMode::Replace)?,
        "restart",
    )?;
    print_action("restarted", &status);
    Ok(())
}

/// Stops the service without disabling boot startup.
pub(crate) fn stop() -> Result<()> {
    let bus = BlockingUnitBus::connect_system()?;
    let job = bus.units().stop(SERVICE_NAME, UnitStartMode::Replace)?;
    match job.wait(JOB_TIMEOUT) {
        Ok(outcome) => {
            let status = job_outcome(outcome, "stop")?;
            print_action("stopped", &status);
            Ok(())
        }
        // A stopped unit can be unloaded before unitbus reads its final status.
        // The completed stop job and missing unit both mean no service remains.
        Err(unitbus::Error::UnitNotFound { unit }) if unit == SERVICE_NAME => {
            println!("{SERVICE_NAME} stopped: inactive (dead)");
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Shows recent service logs and follows new entries from the system journal.
pub(crate) fn log() -> Result<()> {
    let captured_at = unix_micros(SystemTime::now())?;
    let journal = sdjournal::Journal::open_default()?;
    let mut query = journal.query();
    query
        .match_unit(SERVICE_NAME)
        .seek_tail()
        .limit(RECENT_LOG_LIMIT);

    let mut recent = query.collect_owned()?;
    let newest_cursor = recent.first().map(EntryOwned::cursor).transpose()?;
    recent.reverse();
    for entry in &recent {
        print_log_entry(entry.get("MESSAGE"), entry.get("_PID"));
    }

    let mut live = LiveJournal::open_default()?;
    let mut filter = live.filter();
    filter.match_unit(SERVICE_NAME);

    let mut options = SubscriptionOptions::new(filter);
    if let Some(cursor) = newest_cursor {
        options.after_cursor(cursor);
    } else {
        options.since_realtime(captured_at);
    }

    let subscription = live.subscribe_with_options(options)?;
    loop {
        live.poll_once()?;
        loop {
            match subscription.try_recv() {
                Ok(entry) => {
                    let entry = entry?;
                    print_log_entry(entry.get("MESSAGE"), entry.get("_PID"));
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(io::Error::other("system journal subscription closed").into());
                }
            }
        }
    }
}

/// Shows service and process state through systemd's D-Bus API.
pub(crate) fn status() -> Result<()> {
    let bus = BlockingUnitBus::connect_system()?;
    let status = bus.units().get_status(SERVICE_NAME)?;

    match status.description.as_deref() {
        Some(description) => println!("{} - {description}", status.id),
        None => println!("{}", status.id),
    }
    println!(
        "  Loaded: {} ({})",
        status.load_state.as_str(),
        status.fragment_path.as_deref().unwrap_or("no unit file")
    );
    println!(
        "  Active: {} ({})",
        status.active_state.as_str(),
        status.sub_state.as_deref().unwrap_or("unknown")
    );

    if let Some(pid) = status.main_pid.filter(|pid| *pid != 0) {
        println!("  Main PID: {pid}");
    }
    if let Some(result) = status.result.as_deref() {
        println!("  Result: {result}");
    }
    if let Some(restarts) = status.n_restarts.filter(|count| *count != 0) {
        println!("  Restarts: {restarts}");
    }

    Ok(())
}

fn install(bus: &BlockingUnitBus, config: &BootArgs, command: ServiceCommand) -> Result<()> {
    let identity = invoking_user();
    let spec = service_unit(env::current_exe()?, command, config, identity)?;
    let report = bus
        .config()
        .install_service_unit(spec, Default::default())?;

    let state = if report.wrote.changed {
        "updated"
    } else {
        "unchanged"
    };
    println!("systemd unit {state}: {}", report.wrote.path_written);
    Ok(())
}

/// Returns the original user when the command is run through sudo.
///
/// Direct root invocations leave the service identity unset so executables and
/// certificate files under `/root` remain accessible.
fn invoking_user() -> Option<ServiceIdentity> {
    let uid = env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid = env::var("SUDO_GID").ok()?.parse().ok()?;

    (uid != 0).then_some(ServiceIdentity { uid, gid })
}

fn service_unit(
    executable: PathBuf,
    command: ServiceCommand,
    config: &BootArgs,
    identity: Option<ServiceIdentity>,
) -> Result<ServiceUnitSpec> {
    let ServiceCommand {
        mut arguments,
        working_directory,
        environment,
    } = command;
    let mut exec_start = Vec::with_capacity(arguments.len().saturating_add(1));
    exec_start.push(path_arg(executable, "server executable")?);
    exec_start.append(&mut arguments);

    for argument in &mut exec_start {
        escape_systemd_expansions(argument);
    }

    let mut extra_service = Vec::with_capacity(12);
    // unitbus 0.1.7 quotes this directive, but systemd treats those quotes as path bytes.
    // https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#WorkingDirectory=
    extra_service.push(format!("WorkingDirectory={working_directory}"));

    let mut capabilities = Vec::with_capacity(3);
    if config.bind.port() < 1024 {
        capabilities.push("CAP_NET_BIND_SERVICE");
    }
    if config.cidr.is_some() {
        capabilities.push("CAP_NET_ADMIN");
    }
    if matches!(config.fallback.as_ref(), Some(Fallback::Interface(_))) {
        capabilities.push("CAP_NET_RAW");
    }
    if !capabilities.is_empty() {
        let capabilities = capabilities.join(" ");
        extra_service.push(format!("AmbientCapabilities={capabilities}"));
        extra_service.push(format!("CapabilityBoundingSet={capabilities}"));
    }

    // StateDirectory provides private writable state outside ProtectSystem=strict.
    // https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#StateDirectory=
    extra_service.extend([
        "StateDirectory=vproxy".to_owned(),
        "StateDirectoryMode=0700".to_owned(),
        "UMask=0077".to_owned(),
        "NoNewPrivileges=yes".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=read-only".to_owned(),
    ]);

    let mut spec = ServiceUnitSpec::default();
    spec.unit = SERVICE_NAME.to_owned();
    spec.description = Some("Vproxy HTTP, HTTPS, SOCKS5, and MASQUE proxy server".to_owned());
    spec.after = vec!["network.target".to_owned()];
    spec.service_type = Some(ServiceType::Exec);
    spec.exec_start = exec_start;
    spec.environment = environment;
    spec.restart = Some("on-failure".to_owned());
    spec.restart_sec = Some(3);
    spec.timeout_stop_sec = Some(10);
    spec.standard_output = Some("journal".to_owned());
    spec.standard_error = Some("journal".to_owned());
    spec.wanted_by = vec!["multi-user.target".to_owned()];
    spec.extra_unit = vec!["Documentation=https://github.com/0x676e67/vproxy".to_owned()];
    spec.extra_service = extra_service;

    if let Some(identity) = identity {
        spec.user = Some(identity.uid.to_string());
        spec.group = Some(identity.gid.to_string());
    }

    Ok(spec)
}

fn server_environment() -> Result<BTreeMap<String, String>> {
    let command = BootArgs::augment_args(ClapCommand::new("run"));
    let mut environment = BTreeMap::new();

    for name in command
        .get_arguments()
        .filter_map(|argument| argument.get_env())
    {
        let Some(value) = env::var_os(name) else {
            continue;
        };
        let name = string_arg(name.to_os_string(), "environment variable name")?;
        let value = string_arg(value, "environment variable value")?;
        environment.insert(name, value);
    }

    Ok(environment)
}

fn path_arg(path: PathBuf, description: &'static str) -> Result<String> {
    let path = std::path::absolute(path)?;
    string_arg(path.into_os_string(), description)
}

fn string_arg(value: OsString, description: &'static str) -> Result<String> {
    value.into_string().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} is not valid UTF-8"),
        )
        .into()
    })
}

/// Escapes markers before unitbus applies systemd command-line quoting.
///
/// systemd expands percent specifiers and dollar environment references even
/// though no shell is involved. Doubling them preserves the literal CLI value.
/// https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#Command%20Lines
fn escape_systemd_expansions(argument: &mut String) {
    escape_markers(argument, |character| matches!(character, '%' | '$'));
}

/// Escapes percent specifiers in directives such as `WorkingDirectory`.
///
/// https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#Specifiers
fn escape_systemd_specifiers(value: &mut String) {
    escape_markers(value, |character| character == '%');
}

fn escape_markers(value: &mut String, should_escape: impl Fn(char) -> bool) {
    let extra = value
        .chars()
        .filter(|character| should_escape(*character))
        .count();
    if extra == 0 {
        return;
    }

    let mut escaped = String::with_capacity(value.len().saturating_add(extra));
    for character in value.chars() {
        if should_escape(character) {
            escaped.push(character);
        }
        escaped.push(character);
    }
    *value = escaped;
}

fn wait_for_job(job: BlockingJobHandle, action: &'static str) -> Result<UnitStatus> {
    job_outcome(job.wait(JOB_TIMEOUT)?, action)
}

fn job_outcome(outcome: JobOutcome, action: &'static str) -> Result<UnitStatus> {
    match outcome {
        JobOutcome::Success { unit_status } => Ok(unit_status),
        JobOutcome::Failed {
            unit_status,
            reason,
        } => Err(io::Error::other(format!(
            "systemd failed to {action} {SERVICE_NAME}: {reason:?} (active={}, sub={})",
            unit_status.active_state.as_str(),
            unit_status.sub_state.as_deref().unwrap_or("unknown")
        ))
        .into()),
        JobOutcome::Canceled { unit_status } => Err(io::Error::other(format!(
            "systemd canceled {action} for {SERVICE_NAME} (active={})",
            unit_status.active_state.as_str()
        ))
        .into()),
        _ => Err(io::Error::other(format!(
            "systemd returned an unsupported result while trying to {action} {SERVICE_NAME}"
        ))
        .into()),
    }
}

fn print_action(action: &str, status: &UnitStatus) {
    let state = status.active_state.as_str();
    let sub_state = status.sub_state.as_deref().unwrap_or("unknown");
    println!("{} {action}: {state} ({sub_state})", status.id);
}

fn print_log_entry(message: Option<&[u8]>, pid: Option<&[u8]>) {
    let Some(message) = message else {
        return;
    };
    let message = String::from_utf8_lossy(message);

    if let Some(pid) = pid {
        println!("[{}] {message}", String::from_utf8_lossy(pid));
    } else {
        println!("{message}");
    }
}

fn unix_micros(time: SystemTime) -> Result<u64> {
    let duration = time.duration_since(UNIX_EPOCH).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("system time is before the Unix epoch: {error}"),
        )
    })?;
    u64::try_from(duration.as_micros()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("system timestamp is too large: {error}"),
        )
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_systemd_expansion_markers() {
        let mut value = "100%-$TOKEN".to_owned();
        escape_systemd_expansions(&mut value);
        assert_eq!(value, "100%%-$$TOKEN");
    }

    #[test]
    fn leaves_plain_arguments_unchanged() {
        let mut value = "127.0.0.1:1080".to_owned();
        escape_systemd_expansions(&mut value);
        assert_eq!(value, "127.0.0.1:1080");
    }
}
