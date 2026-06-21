//! Low-level fixed-width byte reads shared across the wire modules.

use std::io::{self, Read};

/// Read a single byte.
pub(crate) fn read_byte<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

/// Read a fixed-size `N`-byte array.
pub(crate) fn read_array<const N: usize, R: Read>(r: &mut R) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf)?;
    Ok(buf)
}
