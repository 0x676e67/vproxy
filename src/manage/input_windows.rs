//! Bounded UTF-16 console input. A high surrogate delivered alone must wait for
//! its low surrogate, not be mistaken for EOF by a bytewise stdin adapter.

use std::io::{self, Read};

use winsafe::{HSTD, WString, co};
use zeroize::{Zeroize, Zeroizing};

/// Preserve the exact input mode for both prompts. GetStdHandle borrows an
/// existing process handle: immediately take it out of the library's close guard
/// so dropping this wrapper cannot close standard input.
pub(super) struct TerminalMode {
    handle: HSTD,
    original: co::CONSOLE,
    active: bool,
}

impl TerminalMode {
    pub(super) fn enter() -> io::Result<Self> {
        let handle = HSTD::GetStdHandle(co::STD_HANDLE::INPUT)
            .map_err(io::Error::other)?
            .leak();
        let original = handle.GetConsoleMode().map_err(io::Error::other)?;
        if original & co::CONSOLE::ENABLE_LINE_INPUT == co::CONSOLE::default() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal is already in raw mode",
            ));
        }
        let mut guard = Self {
            handle,
            original,
            active: true,
        };
        let raw = original
            & !(co::CONSOLE::ENABLE_ECHO_INPUT
                | co::CONSOLE::ENABLE_LINE_INPUT
                | co::CONSOLE::ENABLE_PROCESSED_INPUT);
        if let Err(error) = guard.handle.SetConsoleMode(raw) {
            guard.restore_inner()?;
            return Err(io::Error::other(error));
        }
        Ok(guard)
    }

    pub(super) fn restore(mut self) -> io::Result<()> {
        self.restore_inner()
    }

    fn restore_inner(&mut self) -> io::Result<()> {
        if self.active {
            // Ctrl+C is data in raw mode; Windows will not clear its queued
            // suffix automatically. Restore even if clearing fails.
            let clear = self
                .handle
                .FlushConsoleInputBuffer()
                .map_err(io::Error::other);
            self.handle
                .SetConsoleMode(self.original)
                .map_err(io::Error::other)?;
            self.active = false;
            clear?;
        }
        Ok(())
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        let _ = self.restore_inner();
    }
}

/// One reader spans both prompts. ReadConsole writes at most the fixed WString
/// capacity; count, not NUL termination, determines which UTF-16 units are valid.
pub(super) struct ConsoleInput {
    handle: HSTD,
    buffer: WString,
    position: usize,
    count: usize,
    encoded: Zeroizing<[u8; 4]>,
    encoded_position: usize,
    encoded_len: usize,
}

impl ConsoleInput {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            handle: HSTD::GetStdHandle(co::STD_HANDLE::INPUT)
                .map_err(io::Error::other)?
                .leak(),
            buffer: WString::new_alloc_buf(64),
            position: 0,
            count: 0,
            encoded: Zeroizing::new([0; 4]),
            encoded_position: 0,
            encoded_len: 0,
        })
    }

    fn unit(&mut self) -> io::Result<Option<u16>> {
        if self.position == self.count {
            self.buffer.as_mut_slice().zeroize();
            self.count = usize::try_from(
                self.handle
                    .ReadConsole(&mut self.buffer, None)
                    .map_err(io::Error::other)?,
            )
            .map_err(|_| invalid_unicode())?;
            self.position = 0;
            if self.count == 0 {
                return Ok(None);
            }
        }
        let unit = self
            .buffer
            .as_mut_slice()
            .get_mut(self.position)
            .ok_or_else(invalid_unicode)?;
        let value = *unit;
        unit.zeroize();
        self.position += 1;
        Ok(Some(value))
    }

    fn scalar(&mut self) -> io::Result<Option<char>> {
        let Some(first) = self.unit()? else {
            return Ok(None);
        };
        let value = if (0xd800..=0xdbff).contains(&first) {
            let second = self.unit()?.ok_or_else(invalid_unicode)?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(invalid_unicode());
            }
            0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
        } else {
            u32::from(first)
        };
        char::from_u32(value).map(Some).ok_or_else(invalid_unicode)
    }
}

impl Read for ConsoleInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.encoded_position == self.encoded_len {
            let Some(value) = self.scalar()? else {
                return Ok(0);
            };
            self.encoded_len = value.encode_utf8(&mut *self.encoded).len();
            self.encoded_position = 0;
        }
        output[0] = self.encoded[self.encoded_position];
        self.encoded[self.encoded_position].zeroize();
        self.encoded_position += 1;
        Ok(1)
    }
}

impl Drop for ConsoleInput {
    fn drop(&mut self) {
        self.buffer.as_mut_slice().zeroize();
    }
}

fn invalid_unicode() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-16 console input")
}
