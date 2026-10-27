//! Offline terminal input. No password is accepted in arguments or echoed as a
//! fallback. The terminal stays raw for both password prompts, not one key at a
//! time; a single bounded reader owns input throughout the operation.

use std::{
    io::{self, IsTerminal, Read, Write},
    path::Path,
};

use zeroize::{Zeroize, Zeroizing};

use super::{MAX_PASSWORD_BYTES, validate_names, validate_password};

#[cfg(windows)]
#[path = "input_windows.rs"]
mod windows;
#[cfg(windows)]
use windows::TerminalMode;

/// Collect all first-run input before creating a directory or acquiring a writer.
/// Empty visible inputs select non-secret defaults; confirmation defaults to no.
pub(super) fn initialize(
    directory: &Path,
    name: Option<String>,
    administrator: Option<String>,
) -> io::Result<(String, String, Zeroizing<Vec<u8>>)> {
    require_terminal()?;
    let mut reader = terminal_reader()?;
    let mut output = io::stderr().lock();
    writeln!(
        output,
        "Initialize a local management database (no server will start)."
    )?;
    writeln!(output, "Data directory: {directory:?}")?;
    let name = match name {
        Some(name) => name,
        None => visible_line(
            &mut reader,
            &mut output,
            "Node name [vproxy node]: ",
            128,
            "vproxy node",
        )?,
    };
    let administrator = match administrator {
        Some(administrator) => administrator,
        None => visible_line(
            &mut reader,
            &mut output,
            "Administrator [admin]: ",
            64,
            "admin",
        )?,
    };
    validate_names(&name, &administrator)?;
    writeln!(output, "Node: {name}; administrator: {administrator}")?;
    let answer = visible_line(
        &mut reader,
        &mut output,
        "Create this database? [y/N]: ",
        3,
        "n",
    )?;
    if !answer.eq_ignore_ascii_case("y") && !answer.eq_ignore_ascii_case("yes") {
        return Err(cancelled());
    }
    let password = password_pair(&mut reader, &mut output)?;
    Ok((name, administrator, password))
}

/// Read a new password twice from a real terminal. Redirected automation must
/// explicitly choose `--password-stdin` instead of silently changing input mode.
pub(super) fn password() -> io::Result<Zeroizing<Vec<u8>>> {
    require_terminal()?;
    password_pair(&mut terminal_reader()?, &mut io::stderr().lock())
}

/// Read one existing proxy password without applying new administrator-password
/// rules. Redirected input remains an explicit choice of the diagnostic caller.
pub(super) fn existing_password() -> io::Result<Zeroizing<Vec<u8>>> {
    require_terminal()?;
    let mut reader = terminal_reader()?;
    let mut output = io::stderr().lock();
    let terminal = TerminalMode::enter()?;
    let result = read_existing_password(&mut reader, &mut output);
    // Preserve the same explicit restoration guarantee as the two-prompt path.
    let newline = output.write_all(b"\r\n").and_then(|()| output.flush());
    terminal.restore()?;
    newline?;
    result
}

/// Keep one terminal reader for an entire visible-only guide, including any
/// buffered Windows input. No terminal mode is changed and redirected stdin
/// never silently supplies defaults or confirms an output.
pub(super) fn with_visible_input<T>(
    collect: impl FnOnce(&mut dyn Read, &mut dyn Write) -> io::Result<T>,
) -> io::Result<T> {
    require_terminal()?;
    collect(&mut terminal_reader()?, &mut io::stderr().lock())
}

/// Do not pre-read secrets into std's process-global stdin buffer. On Unix the
/// same synchronous reader calls read(2) directly; Windows owns a fixed UTF-16
/// buffer across visible fields and hidden prompts (including split surrogates).
#[cfg(unix)]
fn terminal_reader() -> io::Result<impl Read> {
    struct Input;
    impl Read for Input {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            rustix::io::read(io::stdin(), output).map_err(Into::into)
        }
    }
    Ok(Input)
}

#[cfg(windows)]
fn terminal_reader() -> io::Result<impl Read> {
    windows::ConsoleInput::new()
}

fn require_terminal() -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interactive setup requires terminal stdin and stderr; supply explicit options for automation",
        ));
    }
    Ok(())
}

/// Bound visible input as well as secrets; reject extra-long or incomplete lines.
pub(super) fn visible_line(
    reader: &mut (impl Read + ?Sized),
    output: &mut (impl Write + ?Sized),
    prompt: &str,
    limit: usize,
    default: &str,
) -> io::Result<String> {
    output.write_all(prompt.as_bytes())?;
    output.flush()?;
    let mut bytes = Vec::with_capacity(limit + 2);
    let mut overlong = false;
    loop {
        let mut byte = [0];
        match reader.read(&mut byte) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "input line is incomplete",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        if !overlong {
            if bytes.len() == limit + 2 {
                overlong = true;
            } else {
                bytes.push(byte[0]);
            }
        }
        if byte[0] == b'\n' {
            break;
        }
    }
    if overlong {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input line is too long",
        ));
    }
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input line is too long",
        ));
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "input must be UTF-8"))?;
    Ok(if value.is_empty() {
        default.to_owned()
    } else {
        value
    })
}

/// Keep no-echo mode across entry, confirmation, mismatch and I/O errors. Restore
/// it explicitly before hashing/storage; Drop retries restoration during unwinding.
fn password_pair(
    reader: &mut impl Read,
    output: &mut impl Write,
) -> io::Result<Zeroizing<Vec<u8>>> {
    writeln!(
        output,
        "Use at least 12 characters (maximum 1024 UTF-8 bytes). Ctrl+C or Ctrl+D cancels; Backspace edits."
    )?;
    output.flush()?;
    let terminal = TerminalMode::enter()?;
    let result = read_pair(reader, output);
    // Even a failed newline write must not bypass explicit mode restoration.
    let newline = output.write_all(b"\r\n").and_then(|()| output.flush());
    terminal.restore()?;
    newline?;
    result
}

fn read_pair(reader: &mut impl Read, output: &mut impl Write) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut skip_lf = false;
    output.write_all(b"New password (hidden): ")?;
    output.flush()?;
    let password = hidden_line(reader, &mut skip_lf)?;
    output.write_all(b"\r\nConfirm password (hidden): ")?;
    output.flush()?;
    let confirmation = hidden_line(reader, &mut skip_lf)?;
    if *password != *confirmation {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passwords do not match; no state was changed",
        ));
    }
    Ok(password)
}

fn read_existing_password(
    reader: &mut impl Read,
    output: &mut impl Write,
) -> io::Result<Zeroizing<Vec<u8>>> {
    output.write_all(b"Existing proxy password (hidden): ")?;
    output.flush()?;
    hidden_line_with(
        reader,
        &mut false,
        255,
        super::connection_test::validate_password,
        "proxy password input is invalid or exceeds 255 UTF-8 bytes",
    )
}

/// Read bounded UTF-8 without a terminal event parser or an unbounded paste
/// buffer. Interrupted reads retry; EOF and cancellation return before any write.
/// Malformed/overlong entries are discarded until Enter rather than leaving the
/// remainder of that line to be echoed after restoring the terminal.
fn hidden_line(reader: &mut impl Read, skip_lf: &mut bool) -> io::Result<Zeroizing<Vec<u8>>> {
    hidden_line_with(
        reader,
        skip_lf,
        MAX_PASSWORD_BYTES,
        validate_password,
        "password input is invalid or exceeds 1024 UTF-8 bytes",
    )
}

/// The terminal editing and bounded-paste behavior is shared; the caller owns
/// the distinct policy for a new administrator or an existing proxy password.
fn hidden_line_with(
    reader: &mut impl Read,
    skip_lf: &mut bool,
    limit: usize,
    validate: fn(&[u8]) -> io::Result<()>,
    invalid_message: &'static str,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut password = Zeroizing::new(Vec::with_capacity(limit));
    let mut pending = Zeroizing::new([0_u8; 4]);
    let mut pending_len = 0;
    let mut rejected = false;
    let mut first = true;
    loop {
        let mut byte = [0];
        match reader.read(&mut byte) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "terminal input ended; no state was changed",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        let value = byte[0];
        byte.zeroize();
        if first {
            first = false;
            let ignore_lf = std::mem::take(skip_lf);
            if ignore_lf && value == b'\n' {
                continue;
            }
        }
        match value {
            3 | 4 => return Err(cancelled()),
            b'\r' | b'\n' => {
                *skip_lf = value == b'\r';
                if rejected || pending_len != 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, invalid_message));
                }
                validate(&password)?;
                return Ok(password);
            }
            _ if rejected => continue,
            8 | 127 => {
                if pending_len != 0 {
                    pending.zeroize();
                    pending_len = 0;
                } else if let Some(start) = password.iter().rposition(|byte| byte & 0xc0 != 0x80) {
                    password[start..].zeroize();
                    password.truncate(start);
                }
                continue;
            }
            _ => {}
        }
        // Only the unfinished scalar is decoded, so a bounded entry does not
        // repeatedly scan the entire password and no lossy replacement is used.
        if pending_len == pending.len() {
            rejected = true;
            continue;
        }
        pending[pending_len] = value;
        pending_len += 1;
        match std::str::from_utf8(&pending[..pending_len]) {
            Ok(value) => {
                if value.chars().any(char::is_control)
                    || password
                        .len()
                        .checked_add(pending_len)
                        .is_none_or(|length| length > limit)
                {
                    rejected = true;
                } else {
                    password.extend_from_slice(&pending[..pending_len]);
                }
                pending.zeroize();
                pending_len = 0;
            }
            Err(error) if error.error_len().is_none() => {}
            Err(_) => rejected = true,
        }
    }
}

fn cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "input cancelled; no state was changed",
    )
}

/// Keep the original Unix attributes until both prompts finish. Restoring with
/// TCSAFLUSH also discards unread kernel input before re-enabling echo/signals.
/// The unbuffered Unix reader leaves no hidden suffix in a std input buffer.
#[cfg(unix)]
struct TerminalMode {
    active: bool,
    original: rustix::termios::Termios,
}

#[cfg(unix)]
impl TerminalMode {
    fn enter() -> io::Result<Self> {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
        let original = tcgetattr(io::stdin())?;
        if !original.local_modes.contains(LocalModes::ICANON) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal is already in raw mode",
            ));
        }
        let mut guard = Self {
            active: true,
            original,
        };
        let mut raw = guard.original.clone();
        raw.make_raw();
        if let Err(error) = tcsetattr(io::stdin(), OptionalActions::Now, &raw) {
            guard.restore_inner()?;
            return Err(error.into());
        }
        Ok(guard)
    }

    fn restore(mut self) -> io::Result<()> {
        self.restore_inner()
    }

    fn restore_inner(&mut self) -> io::Result<()> {
        if self.active {
            rustix::termios::tcsetattr(
                io::stdin(),
                rustix::termios::OptionalActions::Flush,
                &self.original,
            )?;
            self.active = false;
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for TerminalMode {
    fn drop(&mut self) {
        let _ = self.restore_inner();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_input_preserves_unicode_and_backspaces_one_scalar() {
        let mut input =
            "  十二个中文字符作为密码使用😀\x08🙂  \r\n  十二个中文字符作为密码使用🙂  \n"
                .as_bytes();
        let mut skip = false;
        let first = hidden_line(&mut input, &mut skip).unwrap();
        let second = hidden_line(&mut input, &mut skip).unwrap();
        assert_eq!(*first, *second);
        assert_eq!(
            std::str::from_utf8(&first).unwrap(),
            "  十二个中文字符作为密码使用🙂  "
        );
    }

    #[test]
    fn hidden_input_rejects_controls_invalid_utf8_eof_and_cancellation() {
        for input in [
            &b"long enough password\x1b[200~\n"[..],
            &b"long enough password\xff\n"[..],
            &b"long enough password\xe4\n"[..],
            &b"long enough password"[..],
            &b"long enough password\x03"[..],
            &b"long enough password\x04"[..],
            &b"short\n"[..],
        ] {
            assert!(hidden_line(&mut &input[..], &mut false).is_err());
        }
    }

    #[test]
    fn hidden_input_bounds_memory_and_discards_rejected_line_before_returning() {
        let mut overlong = vec![b'x'; MAX_PASSWORD_BYTES + 16];
        overlong.extend_from_slice(b"\nnext line");
        let mut reader = &overlong[..];
        assert!(hidden_line(&mut reader, &mut false).is_err());
        assert_eq!(reader, b"next line");
        let mut exact = vec![b'x'; MAX_PASSWORD_BYTES];
        exact.push(b'\n');
        assert_eq!(
            hidden_line(&mut &exact[..], &mut false).unwrap().len(),
            MAX_PASSWORD_BYTES
        );
    }

    #[test]
    fn hidden_input_retries_interrupted_reads_and_does_not_replace_io_failures() {
        struct InterruptedOnce {
            interrupted: bool,
            input: &'static [u8],
        }
        impl Read for InterruptedOnce {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    Err(io::Error::from(io::ErrorKind::Interrupted))
                } else {
                    self.input.read(bytes)
                }
            }
        }
        let mut reader = InterruptedOnce {
            interrupted: false,
            input: b"long enough password\n",
        };
        assert_eq!(
            &*hidden_line(&mut reader, &mut false).unwrap(),
            b"long enough password"
        );
        struct Failed;
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
        assert_eq!(
            hidden_line(&mut Failed, &mut false).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn existing_proxy_password_accepts_short_secrets_and_preserves_spaces_without_echo() {
        for (input, expected) in [
            ("x\n", "x"),
            ("  short secret  \r\n", "  short secret  "),
            (" 密😀\x08🙂 \n", " 密🙂 "),
        ] {
            let mut output = Vec::new();
            let password = read_existing_password(&mut input.as_bytes(), &mut output).unwrap();
            assert_eq!(&*password, expected.as_bytes());
            assert_eq!(output, b"Existing proxy password (hidden): ");
        }
    }

    #[test]
    fn existing_proxy_password_rejects_invalid_or_overlong_input_and_drains_the_line() {
        for input in [
            &b"\n"[..],
            &b"short\tsecret\n"[..],
            &b"short\xffsecret\n"[..],
            &b"short\xe4\n"[..],
            &b"short\x03"[..],
            &b"short\x04"[..],
            &b"short"[..],
        ] {
            let mut output = Vec::new();
            assert!(read_existing_password(&mut &input[..], &mut output).is_err());
            assert_eq!(output, b"Existing proxy password (hidden): ");
        }
        let mut exact = vec![b'x'; 255];
        exact.push(b'\n');
        assert_eq!(
            read_existing_password(&mut &exact[..], &mut Vec::new())
                .unwrap()
                .len(),
            255
        );
        let mut oversized = vec![b'x'; 256];
        oversized.extend_from_slice(b"\nnext line");
        let mut reader = &oversized[..];
        assert!(read_existing_password(&mut reader, &mut Vec::new()).is_err());
        assert_eq!(reader, b"next line");
    }

    #[test]
    fn visible_input_defaults_and_length_are_bounded() {
        assert_eq!(
            visible_line(&mut &b"\r\n"[..], &mut Vec::new(), "", 4, "node").unwrap(),
            "node"
        );
        assert!(visible_line(&mut &b"12345\n"[..], &mut Vec::new(), "", 4, "").is_err());
        let mut lines = &b"123456789012345\nnext\n"[..];
        assert!(visible_line(&mut lines, &mut Vec::new(), "", 4, "").is_err());
        assert_eq!(lines, b"next\n");
        assert!(visible_line(&mut &b"node"[..], &mut Vec::new(), "", 4, "").is_err());
    }
}
