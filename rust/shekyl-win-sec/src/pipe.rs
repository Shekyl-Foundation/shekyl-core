// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The self-hosted wallet pipe: the server's listener and the client's dial
//! (**WP-D1**, **WP-D3**, **WP-W2**).
//!
//! On Unix the in-process wallet RPC lives on a socket inside a fresh 0700
//! directory. That directory does four jobs, and `WINDOWS_WALLET_SUPPORT.md`
//! §8.1 records that its first enumeration missed the one that matters here:
//! **containment** — nobody else can place an object at the name the client
//! is about to dial. A pipe has no containing directory, so containment is
//! rebuilt from two halves, both in this module:
//!
//! 1. **At creation** — [`OwnerOnlyPipeListener::bind`] creates the first
//!    instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a name already held
//!    by someone else fails loud instead of being joined. A squatted name is
//!    therefore never dialled at all (WP-D3 mitigation 1).
//! 2. **At the dial** — [`open_verified`] opens the pipe and runs
//!    [`PeerCheck::verify`] **before returning the handle**. The CLI cannot
//!    write to a pipe that has not passed, because it never holds one: the
//!    ordering the probe sheet's P-11 asks about is a property of the type,
//!    not of call-site discipline (WP-D3 mitigation 2).
//!
//! The name itself ([`self_hosted_pipe_name`]) is WP-D1: the user's SID goes
//! in literally, so the SID the client reads back off the handle is the SID
//! it derived the name from — one value keys both, and there is no separate
//! expectation to configure wrong. The pid and spawn counter scope instances
//! the way `private_socket_dir`'s name did; they are hygiene, not security
//! (WP-D3 mitigation 3).
//!
//! # Why the dial has no timeout
//!
//! The Unix client bounds reads and writes because its `uds://` form can be
//! pointed at an untrusted external server. Windows ships no external form
//! (§8.1 ruling), and after [`PeerCheck::verify`] returns `Ok` the other end
//! is either this process or a same-user Medium-or-above process, which §6
//! places out of scope. A post-verify hang is a denial of service by an
//! adversary the round does not defend against, so a timeout here would be
//! guarding a path that does not exist.
//!
//! # Verification status
//!
//! Compiles, lints and documents for `x86_64-pc-windows-gnu` on the pinned
//! toolchain. The claims below about what the OS does — that a closed server
//! end reads as EOF on the client, that `first_pipe_instance` refuses a held
//! name cross-process — are claims about documented behaviour until the
//! Windows runner executes the end-to-end test (`rpc_session_e2e`, P-10).

use std::fmt;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT, GENERIC_READ,
    GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_NONE, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

use crate::peer::{PeerCheck, PeerCheckError};
use crate::sddl::{OwnerOnlyDescriptor, SddlError};
use crate::sid::{current_logon_sid, current_user_sid, SidError, SidString};
use crate::PIPE_PREFIX;

/// The name the in-process server listens on and the in-process client dials.
///
/// `\\.\pipe\shekyl-wallet-<user-sid>-<pid>-<spawn>`. The SID is literal
/// (WP-D1); `spawn` is the host's per-process spawn counter so several
/// in-process servers in one process never collide (test binaries; future
/// multi-session hosts), mirroring `private_socket_dir`.
#[must_use]
pub fn self_hosted_pipe_name(owner: &SidString, spawn: u64) -> String {
    format!(
        "{PIPE_PREFIX}{}-{}-{spawn}",
        owner.as_str(),
        std::process::id()
    )
}

/// Why the listener could not be created.
#[derive(Debug)]
pub enum PipeBindError {
    /// The process's own SIDs could not be read.
    Sid(SidError),
    /// The owner-only descriptor could not be built.
    Descriptor(SddlError),
    /// `CreateNamedPipe` failed. `ERROR_ACCESS_DENIED` on the **first**
    /// instance is the loud-failure case WP-D3 (1) exists for: the name is
    /// already held, and this refuses to join it.
    Create(io::Error),
}

impl fmt::Display for PipeBindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sid(e) => write!(
                f,
                "could not identify this process for the wallet RPC pipe: {e}"
            ),
            Self::Descriptor(e) => write!(f, "{e}"),
            Self::Create(e) if os_code(e) == Some(ERROR_ACCESS_DENIED) => f.write_str(
                "the wallet RPC pipe name is already held by another process and Shekyl \
                 refuses to join it. Another wallet session may be running; if not, \
                 something else has taken the name.",
            ),
            Self::Create(e) => write!(f, "could not create the wallet RPC pipe: {e}"),
        }
    }
}

impl std::error::Error for PipeBindError {}

impl From<SidError> for PipeBindError {
    fn from(e: SidError) -> Self {
        Self::Sid(e)
    }
}

impl From<SddlError> for PipeBindError {
    fn from(e: SddlError) -> Self {
        Self::Descriptor(e)
    }
}

/// The server side: one pipe name, served create-instance-per-accept.
///
/// A named pipe is not a socket with a backlog. Each client connection
/// consumes one *instance*; to keep accepting, the server creates the next
/// instance itself. [`Self::accept`] does that, and does it **before**
/// handing the connected instance out, so the name stays held continuously.
pub struct OwnerOnlyPipeListener {
    name: String,
    descriptor: OwnerOnlyDescriptor,
    /// The instance currently waiting for a client. `None` only after a
    /// successor could not be created, in which case the next `accept`
    /// retries and surfaces the error.
    waiting: Option<NamedPipeServer>,
}

impl OwnerOnlyPipeListener {
    /// Create the first instance at `name` — owner-only descriptor, session
    /// scoped DACL, Medium label (WP-D1/D4/D6) — refusing a name that is
    /// already held (WP-D3 mitigation 1).
    ///
    /// Must be called inside a tokio runtime with I/O enabled; the instance
    /// registers with it.
    pub fn bind(name: String) -> Result<Self, PipeBindError> {
        let owner = current_user_sid()?;
        let logon = current_logon_sid()?;
        let descriptor = OwnerOnlyDescriptor::new(&owner, &logon)?;
        let first = create_instance(&name, &descriptor, true).map_err(PipeBindError::Create)?;
        Ok(Self {
            name,
            descriptor,
            waiting: Some(first),
        })
    }

    /// The name this listener holds.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Wait for a client, then return the connected instance.
    ///
    /// The successor instance is created while the connected one still
    /// exists, so there is no moment at which the name is free for someone
    /// else to take. If the successor cannot be created the connected client
    /// is still served, and the next call retries (and reports) the create.
    pub async fn accept(&mut self) -> io::Result<NamedPipeServer> {
        let waiting = match self.waiting.take() {
            Some(instance) => instance,
            None => create_instance(&self.name, &self.descriptor, false)?,
        };
        if let Err(e) = waiting.connect().await {
            // The instance is still usable; keep it for the next call rather
            // than leaking the name.
            self.waiting = Some(waiting);
            return Err(e);
        }
        self.waiting = create_instance(&self.name, &self.descriptor, false).ok();
        Ok(waiting)
    }
}

/// One instance at `name`, carrying `descriptor`.
///
/// Every instance gets the same descriptor — the DACL and label are
/// per-instance on Windows, so setting them once on the first would leave
/// every later instance at the OS default.
fn create_instance(
    name: &str,
    descriptor: &OwnerOnlyDescriptor,
    first: bool,
) -> io::Result<NamedPipeServer> {
    // SAFETY: `descriptor.attributes_ptr()` is valid for as long as
    // `descriptor` is borrowed, which outlives this call, and `CreateNamedPipe`
    // reads the attributes only during the call.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            // tokio's default, restated so it is a decision rather than an
            // inheritance: `PIPE_REJECT_REMOTE_CLIENTS` is a second fence
            // against the `IPC$` path WP-D6's logon-SID grant already closes.
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                descriptor.attributes_ptr().cast_mut().cast(),
            )
    }
}

/// Why the client refused to dial, or was refused.
#[derive(Debug)]
pub enum DialError {
    /// This process's own SID could not be read, so there is nothing to
    /// compare the pipe's owner against.
    Sid(SidError),
    /// Nothing is listening at the name.
    NotFound,
    /// Every instance was busy and none freed within the bounded wait.
    Busy,
    /// Any other `CreateFile` failure.
    Open(io::Error),
    /// The pipe exists and was opened, and the peer check refused it. The
    /// handle was closed without a byte written.
    Refused(PeerCheckError),
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sid(e) => write!(f, "could not identify this process for the peer check: {e}"),
            Self::NotFound => f.write_str("no wallet RPC pipe is listening at the expected name"),
            Self::Busy => write!(
                f,
                "the wallet RPC pipe is busy and did not free up within {} ms",
                BUSY_WAIT_MS * BUSY_RETRIES
            ),
            Self::Open(e) => write!(f, "could not open the wallet RPC pipe: {e}"),
            // The peer check's own message already names the property and
            // the remedy (rule 82); wrapping it would bury that.
            Self::Refused(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DialError {}

impl From<SidError> for DialError {
    fn from(e: SidError) -> Self {
        Self::Sid(e)
    }
}

/// A pipe handle that has passed [`PeerCheck::verify`].
///
/// Constructible only by [`open_verified`]; the [`PeerCheck`] inside is the
/// proof, held so the type cannot exist without it. Reads and writes go
/// straight to the synchronous handle — HTTP/1.1 with `Connection: close`,
/// where the server closing its end reads as EOF here.
pub struct VerifiedPipe {
    file: File,
    _verified: PeerCheck,
}

impl io::Read for VerifiedPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl io::Write for VerifiedPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// How long one `WaitNamedPipe` blocks when every instance is busy.
const BUSY_WAIT_MS: u32 = 5_000;
/// How many such waits before giving up. The in-process server keeps a
/// spare instance listening at all times, so busy is a race between two
/// concurrent clients of the same process, which the CLI never is.
const BUSY_RETRIES: u32 = 3;

/// Open the pipe at `name` and verify it **before** returning it.
///
/// The owner must be this process's user SID and the integrity label at
/// least Medium (WP-D4); otherwise the handle is closed and the refusal is
/// returned with no byte written. This is the dial-side half of containment
/// (module docs) and the only pipe-open path `shekyl-cli` has.
pub fn open_verified(name: &str) -> Result<VerifiedPipe, DialError> {
    let me = current_user_sid()?;
    let file = open_pipe_handle(name)?;
    // SAFETY: `file` owns a live handle to a pipe this process just opened,
    // and it outlives the call.
    let verified = unsafe { PeerCheck::verify(file.as_raw_handle().cast(), &me) }
        .map_err(DialError::Refused)?;
    Ok(VerifiedPipe {
        file,
        _verified: verified,
    })
}

/// `CreateFile` on the pipe name, synchronous, with a bounded busy-wait.
fn open_pipe_handle(name: &str) -> Result<File, DialError> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut busy_waits = 0;
    loop {
        // SAFETY: `wide` is NUL-terminated and outlives the call; every other
        // argument is a constant or null. No `FILE_FLAG_OVERLAPPED`, so the
        // handle is synchronous and `File` can drive it.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_NONE,
                std::ptr::null(),
                OPEN_EXISTING,
                // Identification-level impersonation only. The server is
                // meant to be us, but the whole point of the peer check is
                // that it might not be — and a server that is not us should
                // not be able to act as us while the check is still running.
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            // SAFETY: a fresh, valid, owned handle; `File` closes it exactly
            // once, including on the refusal path in `open_verified`.
            return Ok(unsafe { File::from_raw_handle(handle) });
        }
        let err = io::Error::last_os_error();
        match os_code(&err) {
            Some(ERROR_FILE_NOT_FOUND) => return Err(DialError::NotFound),
            Some(ERROR_PIPE_BUSY) if busy_waits < BUSY_RETRIES => {
                busy_waits += 1;
                // SAFETY: `wide` as above. Blocks for at most `BUSY_WAIT_MS`.
                let freed = unsafe { WaitNamedPipeW(wide.as_ptr(), BUSY_WAIT_MS) };
                if freed == 0 {
                    let wait_err = io::Error::last_os_error();
                    return Err(if os_code(&wait_err) == Some(ERROR_SEM_TIMEOUT) {
                        DialError::Busy
                    } else {
                        DialError::Open(wait_err)
                    });
                }
            }
            Some(ERROR_PIPE_BUSY) => return Err(DialError::Busy),
            _ => return Err(DialError::Open(err)),
        }
    }
}

/// The Win32 error code behind an `io::Error`, as the `u32` the constants
/// are typed as. `None` for a non-OS error or a negative code.
fn os_code(err: &io::Error) -> Option<u32> {
    err.raw_os_error().and_then(|code| u32::try_from(code).ok())
}
