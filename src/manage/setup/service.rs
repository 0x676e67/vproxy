//! Reviewable per-user systemd unit; rendering never contacts the service manager.
//!
//! The unit must run as the account that prepared the node and owns its private
//! files. It neither changes identity nor supplies privileges. `Type=exec` only
//! confirms process execution: HTTPS readiness still requires a separate check.

use std::{io, path::Path};

/// Render direct preflight and server invocations for a Linux user service.
///
/// The executable must be an absolute UTF-8 path; all values must be free of
/// control characters. Arguments remain separate, including empty values, and
/// are never interpreted by a shell. The caller must restrict use to Linux and
/// validate that the current account can access the plan's local inputs.
pub(super) fn render(
    executable: &Path,
    check_arguments: &[String],
    serve_arguments: &[String],
) -> io::Result<String> {
    let executable_text = executable.to_str().ok_or_else(invalid_value)?;
    if executable_text.is_empty()
        || !executable.is_absolute()
        || std::iter::once(executable_text)
            .chain(check_arguments.iter().map(String::as_str))
            .chain(serve_arguments.iter().map(String::as_str))
            .any(|value| value.chars().any(char::is_control))
    {
        return Err(invalid_value());
    }

    let check = command(executable_text, check_arguments);
    let serve = command(executable_text, serve_arguments);
    Ok(format!(
        "[Unit]\n\
         Description=Vproxy node management\n\
         \n\
         [Service]\n\
         Type=exec\n\
         WorkingDirectory=/\n\
         UMask=0077\n\
         NoNewPrivileges=yes\n\
         ExecStartPre={check}\n\
         ExecStart={serve}\n\
         Restart=on-failure\n\
         RestartSec=3s\n\
         TimeoutStopSec=60s\n\
         KillMode=control-group\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    ))
}

fn invalid_value() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "setup service values require an absolute UTF-8 executable and no control characters",
    )
}

fn command(executable: &str, arguments: &[String]) -> String {
    // The ':' prefix disables environment expansion for both argv[0] and all
    // arguments. The executable path is resolved separately from argv: '$$'
    // there would refer to a different file instead of escaping a literal '$'.
    // https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#Command%20Lines
    let mut command = String::from(":");
    command.push_str(&quote(executable));
    for argument in arguments {
        command.push(' ');
        command.push_str(&quote(argument));
    }
    command
}

/// The ':' prefix leaves dollars literal, but percent specifiers still expand.
/// Escape systemd's quotes, backslashes and specifiers, not shell metacharacters.
/// <https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#Command%20Lines>
fn quote(value: &str) -> String {
    let mut quoted = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' | '"' => quoted.push('\\'),
            '%' => quoted.push(character),
            _ => {}
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn executable() -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            r"C:\Program files\工具 %x $ENV\vproxy.exe"
        } else {
            "/opt/Program files/工具 %x $ENV/vproxy"
        })
    }

    #[test]
    fn quotes_expansion_markers_and_metacharacters_without_a_shell() -> io::Result<()> {
        let check = ["manage", "setup", "check", "--input", ""].map(String::from);
        let serve = [
            "manage",
            "serve",
            "--name",
            r#"路径 O'Brien \ \" %% %n $USER ${HOME}; /bin/false #"#,
            ";",
        ]
        .map(String::from);
        let unit = render(&executable(), &check, &serve)?;
        let quoted_executable = if cfg!(windows) {
            r#""C:\\Program files\\工具 %%x $ENV\\vproxy.exe""#
        } else {
            r#""/opt/Program files/工具 %%x $ENV/vproxy""#
        };
        assert!(unit.contains(&format!(
            "ExecStartPre=:{quoted_executable} \"manage\" \"setup\" \"check\" \"--input\" \"\"\n"
        )));
        assert!(unit.contains(&format!(
            "ExecStart=:{quoted_executable} {}\n",
            r#""manage" "serve" "--name" "路径 O'Brien \\ \\\" %%%% %%n $USER ${HOME}; /bin/false #" ";""#,
        )));
        assert!(unit.contains("Type=exec\nWorkingDirectory=/\nUMask=0077\n"));
        assert!(unit.contains("NoNewPrivileges=yes\n"));
        assert!(unit.contains("TimeoutStopSec=60s\nKillMode=control-group\n"));
        assert!(unit.ends_with("[Install]\nWantedBy=default.target\n"));
        for unexpected in [
            "User=",
            "Group=",
            "StateDirectory=",
            "Capabilities=",
            "ProtectSystem=",
            "/bin/sh",
        ] {
            assert!(!unit.contains(unexpected));
        }
        Ok(())
    }

    #[test]
    fn rejects_controls_in_every_input_before_rendering() {
        for control in ['\n', '\r', '\0', '\t', '\u{1b}', '\u{7f}', '\u{85}'] {
            let argument = format!("before{control}after");
            let arguments = [argument.clone()];
            assert_eq!(
                render(&executable(), &arguments, &[])
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
            assert_eq!(
                render(&executable(), &[], &arguments)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
            let mut path = executable().into_os_string();
            path.push(argument);
            assert_eq!(
                render(Path::new(&path), &[], &[])
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
        }
    }

    #[test]
    fn rejects_empty_relative_or_non_utf8_executable_paths() {
        for path in ["", "vproxy", "../vproxy"] {
            assert_eq!(
                render(Path::new(path), &[], &[])
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
        }

        #[cfg(unix)]
        let invalid = {
            use std::{ffi::OsString, os::unix::ffi::OsStringExt};
            PathBuf::from(OsString::from_vec(vec![b'/', 0xff]))
        };
        #[cfg(windows)]
        let invalid = {
            use std::{ffi::OsString, os::windows::ffi::OsStringExt};
            PathBuf::from(OsString::from_wide(&[0x43, 0x3a, 0x5c, 0xd800]))
        };
        #[cfg(any(unix, windows))]
        assert_eq!(
            render(&invalid, &[], &[]).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
}
