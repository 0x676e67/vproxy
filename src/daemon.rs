use std::{
    fs::{self, File, Permissions},
    io::{self, BufRead, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use daemonize::Daemonize;
use nix::{
    sys::signal,
    unistd::{Pid, Uid},
};

use crate::{BootArgs, server};

const BIN_NAME: &str = env!("CARGO_PKG_NAME");
const DEFAULT_PID_PATH: &str = concat!("/var/run/", env!("CARGO_PKG_NAME"), ".pid");
const DEFAULT_STDOUT_PATH: &str = concat!("/var/run/", env!("CARGO_PKG_NAME"), ".out");
const DEFAULT_STDERR_PATH: &str = concat!("/var/run/", env!("CARGO_PKG_NAME"), ".err");

pub struct Daemon {
    pid_file: PathBuf,
    stdout_file: PathBuf,
    stderr_file: PathBuf,
}

impl Default for Daemon {
    fn default() -> Self {
        Daemon {
            pid_file: PathBuf::from(DEFAULT_PID_PATH),
            stdout_file: PathBuf::from(DEFAULT_STDOUT_PATH),
            stderr_file: PathBuf::from(DEFAULT_STDERR_PATH),
        }
    }
}

impl Daemon {
    /// Start the daemon
    pub fn start(&self, config: BootArgs) -> crate::Result<()> {
        if let Some(pid) = self.pid()? {
            println!("{BIN_NAME} is already running with pid: {pid}");
            return Ok(());
        }

        Daemon::root();

        let pid_file = File::create(&self.pid_file)?;
        pid_file.set_permissions(Permissions::from_mode(0o755))?;

        let stdout = File::create(&self.stdout_file)?;
        stdout.set_permissions(Permissions::from_mode(0o755))?;

        let stderr = File::create(&self.stderr_file)?;
        stderr.set_permissions(Permissions::from_mode(0o755))?;

        let mut daemonize = Daemonize::new()
            .pid_file(&self.pid_file)
            .chown_pid_file(true)
            .umask(0o777)
            .stdout(stdout)
            .stderr(stderr)
            .privileged_action(|| "Executed before drop privileges");

        if let Ok(user) = std::env::var("SUDO_USER") {
            if let Ok(Some(real_user)) = nix::unistd::User::from_name(&user) {
                daemonize = daemonize
                    .user(real_user.name.as_str())
                    .group(real_user.gid.as_raw());
            }
        }

        if let Some(err) = daemonize.start().err() {
            eprintln!("Error: {err}");
            std::process::exit(-1)
        }

        server::run(config)
    }

    /// Stop the daemon
    pub fn stop(&self) -> crate::Result<()> {
        Daemon::root();

        if let Some(pid) = self.pid()? {
            let pid = pid.parse::<i32>()?;
            for _ in 0..360 {
                if signal::kill(Pid::from_raw(pid), signal::SIGINT).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1))
            }
        }

        if let Some(err) = fs::remove_file(&self.pid_file).err() {
            if !matches!(err.kind(), io::ErrorKind::NotFound) {
                println!("failed to remove pid file: {err}");
            }
        }

        Ok(())
    }
    /// Restart the daemon
    pub fn restart(&self, config: BootArgs) -> crate::Result<()> {
        self.stop()?;

        const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

        for i in 0..30 {
            print!("\r{}", SPINNER[i % 4]);
            io::stdout().flush()?;
            std::thread::sleep(Duration::from_millis(100));
        }

        print!("\r \r");
        io::stdout().flush()?;

        self.start(config)
    }

    /// Show the status of the daemon
    pub fn status(&self) -> crate::Result<()> {
        match self.pid()? {
            None => println!("{BIN_NAME} is not running"),
            Some(pid) => {
                let mut sys = sysinfo::System::new();
                sys.refresh_all();

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
        }
        Ok(())
    }

    /// Show the log of the daemon
    pub fn log(&self) -> crate::Result<()> {
        fn read_and_print_file(file_path: &Path, placeholder: &str) -> crate::Result<()> {
            if !file_path.exists() {
                return Ok(());
            }

            let metadata = fs::metadata(file_path)?;
            if metadata.len() == 0 {
                return Ok(());
            }

            let file = File::open(file_path)?;
            let reader = io::BufReader::new(file);
            let mut start = true;

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

        read_and_print_file(&self.stdout_file, "STDOUT>")?;
        read_and_print_file(&self.stderr_file, "STDERR>")?;

        Ok(())
    }

    fn pid(&self) -> crate::Result<Option<String>> {
        if let Ok(data) = fs::read(&self.pid_file) {
            let binding = String::from_utf8(data)?;
            return Ok(Some(binding.trim().to_string()));
        }
        Ok(None)
    }

    fn root() {
        if !Uid::effective().is_root() {
            println!("You must run this executable with root permissions");
            std::process::exit(-1)
        }
    }
}
