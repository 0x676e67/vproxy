use std::{io, path::Path};

/// Render operator-run scripts that stop if the read-only check fails.
/// The executable must be an absolute UTF-8 path; every value must be free of
/// control characters. Quoting preserves empty arguments and shell metacharacters.
pub(super) fn render(
    executable: &Path,
    check_arguments: &[String],
    serve_arguments: &[String],
) -> io::Result<(String, String)> {
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

    let posix_check = command(executable_text, check_arguments, posix_quote);
    let posix_serve = command(executable_text, serve_arguments, posix_quote);
    let powershell_check = command(executable_text, check_arguments, powershell_quote);
    let powershell_serve = command(executable_text, serve_arguments, powershell_quote);
    // A PowerShell host with missing PATHEXT can skip even an absolute native
    // executable without setting LASTEXITCODE. Never inherit null or stale success.
    Ok((
        format!("#!/bin/sh\nset -eu\n{posix_check}\nexec {posix_serve}\n"),
        format!(
            "$ErrorActionPreference = 'Stop'\n$LASTEXITCODE = 1\n& {powershell_check}\nif ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}\n$LASTEXITCODE = 1\n& {powershell_serve}\nexit $LASTEXITCODE\n"
        ),
    ))
}

fn invalid_value() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "setup script values require an absolute UTF-8 executable and no control characters",
    )
}

/// Read compatibility for the two exact generated templates. Inputs cannot
/// contain line breaks, so removing sentinel lines cannot alter quoted argv.
/// New plans always use the guarded template; existing files are never repaired.
pub(super) fn powershell_matches(actual: &[u8], expected: &str) -> bool {
    actual == expected.as_bytes()
        || actual == expected.replace("$LASTEXITCODE = 1\n", "").as_bytes()
}

fn command(executable: &str, arguments: &[String], quote: fn(&str) -> String) -> String {
    let mut command = quote(executable);
    for argument in arguments {
        command.push(' ');
        command.push_str(&quote(argument));
    }
    command
}

fn posix_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn powershell_quote(value: &str) -> String {
    let mut quoted = String::from("'");
    for character in value.chars() {
        quoted.push(character);
        // PowerShell also treats these smart quotes as single-quote delimiters.
        // Double the original character so the literal keeps its exact value.
        if matches!(
            character,
            '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}'
        ) {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn executable() -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            r"C:\Program files\工具 O'Brien\vproxy.exe"
        } else {
            "/opt/Program files/工具 O'Brien/vproxy"
        })
    }

    #[test]
    fn preserves_hostile_values_as_distinct_arguments_in_both_shells() -> io::Result<()> {
        let check_arguments = [
            "manage",
            "check",
            "--config",
            r"C:\A b\路径\O'Brien\$x`cmd`\config.toml",
            "",
        ]
        .map(String::from);
        let serve_arguments = ["serve", "--name", r"路径 '$x' `tick` \end"].map(String::from);
        let (posix, powershell) = render(&executable(), &check_arguments, &serve_arguments)?;
        let (posix_executable, powershell_executable) = if cfg!(windows) {
            (
                r"'C:\Program files\工具 O'\''Brien\vproxy.exe'",
                r"'C:\Program files\工具 O''Brien\vproxy.exe'",
            )
        } else {
            (
                r"'/opt/Program files/工具 O'\''Brien/vproxy'",
                r"'/opt/Program files/工具 O''Brien/vproxy'",
            )
        };
        assert_eq!(
            posix,
            format!(
                "#!/bin/sh\nset -eu\n{posix_executable} {}\nexec {posix_executable} {}\n",
                r"'manage' 'check' '--config' 'C:\A b\路径\O'\''Brien\$x`cmd`\config.toml' ''",
                r"'serve' '--name' '路径 '\''$x'\'' `tick` \end'",
            )
        );
        assert_eq!(
            powershell,
            format!(
                "$ErrorActionPreference = 'Stop'\n$LASTEXITCODE = 1\n& {powershell_executable} {}\nif ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}\n$LASTEXITCODE = 1\n& {powershell_executable} {}\nexit $LASTEXITCODE\n",
                r"'manage' 'check' '--config' 'C:\A b\路径\O''Brien\$x`cmd`\config.toml' ''",
                r"'serve' '--name' '路径 ''$x'' `tick` \end'",
            )
        );
        Ok(())
    }

    #[test]
    fn quotes_every_powershell_single_quote_delimiter_before_separators() {
        for (value, expected) in [
            ("left'; marker; #", "'left''; marker; #'"),
            ("left‘; marker; #", "'left‘‘; marker; #'"),
            ("left’; marker; #", "'left’’; marker; #'"),
            ("left‚; marker; #", "'left‚‚; marker; #'"),
            ("left‛; marker; #", "'left‛‛; marker; #'"),
            (
                r"路径 '‘’‚‛; $value `literal` \end #",
                r"'路径 ''‘‘’’‚‚‛‛; $value `literal` \end #'",
            ),
        ] {
            assert_eq!(powershell_quote(value), expected);
        }
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
    fn rejects_empty_or_relative_executables() {
        for path in ["", "vproxy", "../vproxy"] {
            assert_eq!(
                render(Path::new(path), &[], &[])
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
        }
    }

    #[test]
    fn rejects_non_utf8_executable_paths() {
        #[cfg(unix)]
        let path = {
            use std::{ffi::OsString, os::unix::ffi::OsStringExt};
            PathBuf::from(OsString::from_vec(vec![b'/', 0xff]))
        };
        #[cfg(windows)]
        let path = {
            use std::{ffi::OsString, os::windows::ffi::OsStringExt};
            PathBuf::from(OsString::from_wide(&[0x43, 0x3a, 0x5c, 0xd800]))
        };
        #[cfg(any(unix, windows))]
        assert_eq!(
            render(&path, &[], &[]).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
}
