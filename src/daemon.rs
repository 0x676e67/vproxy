use crate::{BIN_NAME, BootArgs, serve};
use daemonize::Daemonize;
use nix::sys::signal;
use nix::unistd::{Pid, Uid, User};
use std::{
    fs::{File, Permissions},
    os::unix::fs::PermissionsExt,
    path::Path,
};

const PID_PATH: &str = concat!("/var/run/", env!("CARGO_PKG_NAME"), ".pid");
const DEFAULT_STDOUT_PATH: &str = concat!("/var/run/", env!("CARGO_PKG_NAME"), ".out");
const DEFAULT_STDERR_PATH: &str = concat!("/var/run/", env!("CARGO_PKG_NAME"), ".err");

#[inline(always)]
fn pid() -> Option<String> {
    if let Ok(data) = std::fs::read(PID_PATH) {
        let binding = String::from_utf8(data).expect("pid file is not utf8");
        return Some(binding.trim().to_string());
    }
    None
}

#[inline(always)]
pub fn check_root() {
    if !Uid::effective().is_root() {
        println!("You must run this executable with root permissions");
        std::process::exit(-1)
    }
}

pub fn start(args: BootArgs) -> crate::Result<()> {
    if let Some(pid) = pid() {
        println!("{BIN_NAME} is already running with pid: {pid}");
        return Ok(());
    }

    check_root();

    let pid_file = File::create(PID_PATH)?;
    pid_file.set_permissions(Permissions::from_mode(0o755))?;

    let stdout = File::create(DEFAULT_STDOUT_PATH)?;
    stdout.set_permissions(Permissions::from_mode(0o755))?;

    let stderr = File::create(DEFAULT_STDERR_PATH)?;
    stdout.set_permissions(Permissions::from_mode(0o755))?;

    let mut daemonize = Daemonize::new()
        .pid_file(PID_PATH) // Every method except `new` and `start`
        .chown_pid_file(true) // is optional, see `Daemonize` documentation
        .umask(0o777) // Set umask, `0o027` by default.
        .stdout(stdout) // Redirect stdout to `/tmp/daemon.out`.
        .stderr(stderr) // Redirect stderr to `/tmp/daemon.err`.
        .privileged_action(|| "Executed before drop privileges");

    let user_name = std::env::var("SUDO_USER")
        .ok()
        .and_then(|user| User::from_name(&user).ok().flatten())
        .or_else(|| User::from_uid(Uid::current()).ok().flatten());

    if let Some(real_user) = user_name {
        daemonize = daemonize
            .user(real_user.name.as_str())
            .group(real_user.gid.as_raw());
    }

    if let Some(err) = daemonize.start().err() {
        eprintln!("Error: {err}");
        std::process::exit(-1)
    }

    serve::run(args)
}

pub fn stop() -> crate::Result<()> {
    check_root();

    if let Some(pid) = pid() {
        let pid = pid.parse::<i32>()?;
        for _ in 0..360 {
            if signal::kill(Pid::from_raw(pid), signal::SIGINT).is_err() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1))
        }
        let _ = std::fs::remove_file(PID_PATH);
    }

    Ok(())
}

pub fn restart(args: BootArgs) -> crate::Result<()> {
    stop()?;
    start(args)
}

pub fn status() -> crate::Result<()> {
    match pid() {
        Some(pid) => {
            let mut sys = sysinfo::System::new();

            // First, we update all information of our `System` struct.
            sys.refresh_all();

            // Display processes ID
            for (raw_pid, process) in sys.processes().iter() {
                if raw_pid.as_u32().eq(&(pid.parse::<u32>()?)) {
                    println!("{:<6} {:<6}  {:<6}", "PID", "CPU(%)", "MEM(MB)");
                    println!(
                        "{:<6}   {:<6.1}  {:<6.1}",
                        raw_pid,
                        process.cpu_usage(),
                        (process.memory() as f64) / 1024.0 / 1024.0
                    );
                }
            }
        }
        None => println!("{BIN_NAME} is not running"),
    }
    Ok(())
}

pub fn log() -> crate::Result<()> {
    fn read_and_print_file(file_path: &'static str, placeholder: &str) -> crate::Result<()> {
        if !Path::new(file_path).exists() {
            return Ok(());
        }

        // Check if the file is empty before opening it
        let metadata = std::fs::metadata(file_path)?;
        if metadata.len() == 0 {
            return Ok(());
        }

        let file = File::open(file_path)?;
        let reader = std::io::BufReader::new(file);
        let mut start = true;

        use std::io::BufRead;

        for line in reader.lines() {
            if let Ok(content) = line {
                if start {
                    start = false;
                    println!("{placeholder}");
                }
                println!("{content}");
            } else if let Err(err) = line {
                eprintln!("Error reading line: {err}");
            }
        }

        Ok(())
    }

    read_and_print_file(DEFAULT_STDOUT_PATH, "STDOUT>")?;

    read_and_print_file(DEFAULT_STDERR_PATH, "STDERR>")?;

    Ok(())
}
