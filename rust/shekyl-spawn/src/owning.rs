// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A daemon's owning connection: the end of a connected pair its launcher
//! handed it, which carries the daemon's life and its readiness, and nothing
//! else (`GUI_SYNC_LANE.md` GS-C3; Rick, 2026-11-12).
//!
//! - **Adoption** ([`adopt`]), first thing in the daemon's process: the end is
//!   checked to be a connected stream socket above the standard streams, and
//!   made close-on-exec (Unix) or not inheritable (Windows), so no child the
//!   daemon starts (the managed Tor among them) holds a copy. A copy in any
//!   other process would keep the connection open after the daemon's death,
//!   and the launcher would never see it.
//! - **Readiness**: the daemon writes [`READY_LINE`] once, when its owner's
//!   leg is bound, served and published; a launcher reads it with
//!   [`read_ready`]. Nothing else is ever written.
//! - **Life**: the daemon reads only to see the close ([`OwningConnection::
//!   wait_for_close`]). The launcher's close or death closes it, and the daemon
//!   stops. Bytes from the launcher are discarded: it is not a control channel.

use std::io::{self, Read, Write};

use crate::pair::End;

/// The one line a daemon writes on its owning connection, once its owner's
/// leg is served: its format and version, as a rendezvous record's first line
/// is.
pub const READY_LINE: &[u8] = b"shekyld-ready 1\n";

/// Why an inherited end cannot be the owning connection. The launcher is the
/// operator, so these are for a clear error, not a defence: a launcher that
/// meant harm would not need this option.
#[derive(Debug)]
pub enum AdoptError {
    /// The number is a standard stream's (0, 1 or 2).
    StandardStream,
    /// The number is not a descriptor or handle this process holds.
    NotOpen,
    /// The descriptor is open and is not a socket (a regular file, a pipe).
    NotSocket,
    /// The socket is not a stream socket.
    NotStream,
    /// The stream socket is not connected.
    NotConnected,
    /// The end could not be checked or made close-on-exec / not inheritable.
    Os(io::Error),
}

impl AdoptError {
    /// The condition, in the operator's words.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::StandardStream => "it is a standard stream's number (0 to 2)".to_owned(),
            Self::NotOpen => "this process holds no descriptor with that number".to_owned(),
            Self::NotSocket => "it is not a socket".to_owned(),
            Self::NotStream => "it is not a stream socket".to_owned(),
            Self::NotConnected => "it is a stream socket with no peer".to_owned(),
            Self::Os(e) => format!("it could not be adopted: {e}"),
        }
    }
}

/// The adopted owning connection.
pub struct OwningConnection(End);

impl OwningConnection {
    /// A second handle on the same connection, close-on-exec / not
    /// inheritable as the first: one for the ready line, one for the wait.
    ///
    /// # Errors
    ///
    /// The duplication failed.
    pub fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Self)
    }

    /// Tell the launcher the daemon is ready: [`READY_LINE`], once.
    ///
    /// # Errors
    ///
    /// The write failed: the launcher is gone, which the close will report.
    pub fn write_ready(&mut self) -> io::Result<()> {
        self.0.write_all(READY_LINE)?;
        self.0.flush()
    }

    /// Block until the launcher closes its end or dies. Bytes it sends are
    /// read and discarded; `discarded` is told how many, each time, so the
    /// caller can say so once. Returns `Ok` at end of stream and the error on
    /// a failed read; both mean the connection is gone.
    ///
    /// # Errors
    ///
    /// The read that failed.
    pub fn wait_for_close(mut self, mut discarded: impl FnMut(usize)) -> io::Result<()> {
        let mut buffer = [0u8; 256];
        loop {
            match self.0.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(n) => discarded(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// Read the launcher's side of readiness on `ours`: `Ok(())` when the daemon
/// wrote [`READY_LINE`], an error when the connection closed first (a start
/// that refused: its exit status and standard error say why) or carried
/// anything else.
///
/// # Errors
///
/// End of stream before the line, a read error, or a different line.
pub fn read_ready(ours: &mut End) -> io::Result<()> {
    let mut line = vec![0u8; READY_LINE.len()];
    ours.read_exact(&mut line)?;
    if line != READY_LINE {
        return Err(io::Error::other(
            "the daemon's owning connection carried something other than its ready line",
        ));
    }
    Ok(())
}

/// Adopt the inherited end numbered `number` as this process's owning
/// connection: check it, then make it close-on-exec (Unix) or not inheritable
/// (Windows) before any child can be spawned.
///
/// # Errors
///
/// [`AdoptError`], naming the condition that failed.
pub fn adopt(number: u64) -> Result<OwningConnection, AdoptError> {
    #[cfg(unix)]
    {
        adopt_unix(number)
    }
    #[cfg(windows)]
    {
        adopt_windows(number)
    }
}

#[cfg(unix)]
fn adopt_unix(number: u64) -> Result<OwningConnection, AdoptError> {
    use std::os::fd::FromRawFd;

    let fd = crate::pair::RawEnd::try_from(number).map_err(|_| AdoptError::NotOpen)?;
    if fd <= crate::pair::LAST_STANDARD_STREAM {
        return Err(AdoptError::StandardStream);
    }
    // SAFETY: `fcntl` with `F_GETFD` reads only this descriptor's flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::EBADF) {
            AdoptError::NotOpen
        } else {
            AdoptError::Os(error)
        });
    }
    // SAFETY: `stat` is plain data; a zeroed value is a valid out-struct, and
    // `fstat` writes it for the open descriptor `fd`.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        return Err(AdoptError::Os(io::Error::last_os_error()));
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(AdoptError::NotSocket);
    }
    let mut kind: libc::c_int = 0;
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .expect("an int's size fits socklen_t");
    // SAFETY: `kind` and `length` are locals of the sizes passed.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut kind).cast::<libc::c_void>(),
            &raw mut length,
        )
    } != 0
    {
        return Err(AdoptError::Os(io::Error::last_os_error()));
    }
    if kind != libc::SOCK_STREAM {
        return Err(AdoptError::NotStream);
    }
    // SAFETY: `sockaddr_storage` is plain data; a zeroed value is a valid
    // out-struct of the length passed.
    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut peer_length = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
        .expect("sockaddr_storage's size fits socklen_t");
    if unsafe {
        libc::getpeername(
            fd,
            (&raw mut peer).cast::<libc::sockaddr>(),
            &raw mut peer_length,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::ENOTCONN) {
            AdoptError::NotConnected
        } else {
            AdoptError::Os(error)
        });
    }
    // SAFETY: `fcntl` with `F_SETFD` changes only this descriptor's flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(AdoptError::Os(io::Error::last_os_error()));
    }
    // SAFETY: `fd` is an open, connected stream socket this process was
    // handed to own; nothing else in it holds the descriptor.
    Ok(OwningConnection(unsafe { End::from_raw_fd(fd) }))
}

#[cfg(windows)]
fn adopt_windows(number: u64) -> Result<OwningConnection, AdoptError> {
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        getpeername, getsockopt, WSAGetLastError, WSAStartup, SOCKADDR_STORAGE, SOCKET,
        SOCK_STREAM, SOL_SOCKET, SO_TYPE, WSADATA, WSAENOTCONN, WSAENOTSOCK,
    };

    if number <= 2 {
        return Err(AdoptError::StandardStream);
    }
    let socket = SOCKET::try_from(number).map_err(|_| AdoptError::NotOpen)?;
    // Winsock must be started before a socket call; std starts it lazily, and
    // nothing in this process may have used the network yet. Reference
    // counted, so a later start by std is harmless.
    // SAFETY: `data` is a local out-struct.
    let mut data: WSADATA = unsafe { std::mem::zeroed() };
    if unsafe { WSAStartup(0x0202, &raw mut data) } != 0 {
        return Err(AdoptError::Os(io::Error::last_os_error()));
    }
    let mut kind: i32 = 0;
    let mut length = i32::try_from(std::mem::size_of::<i32>()).expect("fits");
    // SAFETY: `kind` and `length` are locals of the sizes passed.
    if unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_TYPE,
            (&raw mut kind).cast::<u8>(),
            &raw mut length,
        )
    } != 0
    {
        // SAFETY: reads this thread's last Winsock error.
        let code = unsafe { WSAGetLastError() };
        return Err(if code == WSAENOTSOCK {
            AdoptError::NotSocket
        } else {
            AdoptError::Os(io::Error::from_raw_os_error(code))
        });
    }
    if kind != SOCK_STREAM {
        return Err(AdoptError::NotStream);
    }
    // SAFETY: a zeroed `SOCKADDR_STORAGE` is a valid out-struct of the length
    // passed.
    let mut peer: SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
    let mut peer_length = i32::try_from(std::mem::size_of::<SOCKADDR_STORAGE>()).expect("fits");
    if unsafe { getpeername(socket, (&raw mut peer).cast(), &raw mut peer_length) } != 0 {
        // SAFETY: as above.
        let code = unsafe { WSAGetLastError() };
        return Err(if code == WSAENOTCONN {
            AdoptError::NotConnected
        } else {
            AdoptError::Os(io::Error::from_raw_os_error(code))
        });
    }
    // SAFETY: `socket` is an open, connected stream socket this process was
    // handed to own; nothing else in it holds the handle.
    let end = unsafe { End::from_raw_socket(number) };
    crate::pair::set_inherit_bit(&end, false).map_err(AdoptError::Os)?;
    Ok(OwningConnection(end))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn refused(number: u64) -> AdoptError {
        match adopt(number) {
            Ok(_) => panic!("{number} was adopted"),
            Err(e) => e,
        }
    }

    /// Each condition refuses with its own reason. Red edit: drop the socket
    /// check, and a regular file's descriptor is refused as an OS error, not
    /// as "not a socket".
    #[test]
    fn an_end_that_is_not_a_connected_stream_socket_is_refused() {
        assert!(matches!(refused(1), AdoptError::StandardStream));
        assert!(matches!(refused(1_000_000), AdoptError::NotOpen));
        let file = tempfile_like();
        assert!(matches!(
            refused(u64::try_from(file.as_raw_fd()).unwrap()),
            AdoptError::NotSocket
        ));
        let datagram = std::os::unix::net::UnixDatagram::unbound().unwrap();
        assert!(matches!(
            refused(u64::try_from(datagram.as_raw_fd()).unwrap()),
            AdoptError::NotStream
        ));
        let dir = std::env::temp_dir().join(format!("shekyl-spawn-listen-{}", std::process::id()));
        drop(std::fs::remove_file(&dir));
        let listener = std::os::unix::net::UnixListener::bind(&dir).unwrap();
        assert!(matches!(
            refused(u64::try_from(listener.as_raw_fd()).unwrap()),
            AdoptError::NotConnected
        ));
        drop(listener);
        drop(std::fs::remove_file(&dir));
    }

    /// A connected end is adopted close-on-exec, and readiness and the close
    /// cross it.
    #[test]
    fn a_connected_end_is_adopted_close_on_exec_and_carries_ready_and_close() {
        let (mut ours, theirs) = End::pair().unwrap();
        let number = theirs.as_raw_fd();
        // Hand the descriptor over: the adoption owns it from here.
        std::mem::forget(theirs);
        // Clear the flag, as an inherited descriptor arrives.
        crate::pair::clear_cloexec(number).unwrap();
        let mut owning = adopt(u64::try_from(number).unwrap()).expect("adopted");
        // SAFETY: reads only this descriptor's flags.
        let flags = unsafe { libc::fcntl(number, libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0, "adopted close-on-exec");
        owning.write_ready().unwrap();
        read_ready(&mut ours).expect("the ready line");
        ours.write_all(b"ignored").unwrap();
        drop(ours);
        let mut seen = 0;
        owning.wait_for_close(|n| seen += n).expect("end of stream");
        assert_eq!(seen, 7, "the parent's bytes are read and discarded");
    }

    /// A regular file's open descriptor.
    fn tempfile_like() -> std::fs::File {
        let path = std::env::temp_dir().join(format!("shekyl-spawn-file-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        drop(std::fs::remove_file(&path));
        file
    }
}
