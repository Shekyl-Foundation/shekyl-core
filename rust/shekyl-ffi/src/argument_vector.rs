// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's argument vector (`DAEMON_CONFIG_CUTOVER.md` §2.2, IG-Q2).
//!
//! One value, two sources, and the constructor the Rust process entry will
//! use when DC-Q13 moves `shekyld`'s `main` into Rust:
//!
//! - [`ArgumentVector::from_process_entry`] is what C `main` calls today.
//!   On Unix the pointers are the vector: this image is a staticlib, and
//!   `std::env::args_os` is empty unless `lang_start` ran. On Windows the
//!   vector is `GetCommandLineW`; a C `main` argv there is the active code
//!   page, so the pointers are not read.
//! - [`ArgumentVector::from_narrow_argv`] is the snapshot export's source.
//!   The caller handed over the strings. Unix keeps each argument's bytes.
//!   Windows decodes the active code page.
//! - [`ArgumentVector::from_os_strings`] is the safe constructor. The Rust
//!   process entry collects `std::env::args_os` here, and the Windows
//!   process source does that now, because `GetCommandLineW` does not need
//!   `lang_start`.
//!
//! The count is the length. A null slot is not a shorter vector: every
//! constructor yields a program name and every argument, or [`None`].

use std::ffi::{c_char, c_int, CStr, OsString};

/// The argument vector, program name first.
///
/// Empty is not a value. A start with no program name does not run.
#[derive(Debug)]
#[must_use]
pub struct ArgumentVector {
    args: Vec<OsString>,
}

impl ArgumentVector {
    /// The arguments `main` passed, or [`None`] when they cannot be read.
    ///
    /// On Unix, [`from_narrow_argv`](Self::from_narrow_argv)'s contract.
    /// On Windows the pointers are not read: the vector is
    /// `GetCommandLineW` through `std::env::args_os`, and an empty result
    /// is [`None`].
    ///
    /// # Safety
    ///
    /// On Unix, when `argc >= 1` and `argv` is non-null, `argv` addresses
    /// `argc` pointers and each one is non-null and NUL-terminated for
    /// this call. On Windows `argc` and `argv` are not dereferenced.
    pub unsafe fn from_process_entry(argc: c_int, argv: *const *const c_char) -> Option<Self> {
        #[cfg(windows)]
        {
            let _ = (argc, argv);
            Self::from_os_strings(std::env::args_os().collect())
        }
        #[cfg(not(windows))]
        {
            // SAFETY: the caller's contract.
            unsafe { Self::from_narrow_argv(argc, argv) }
        }
    }

    /// A caller-supplied narrow argument list, program first.
    ///
    /// Unix keeps each argument's bytes, so a non-UTF-8 argument reaches
    /// the parser's encoding refusal. Windows decodes the active code page
    /// and returns [`None`] for a byte that page cannot represent.
    /// [`None`] is also `argc < 1`, a null `argv`, a pointer the slice
    /// bound refuses, or any null slot. The terminating null a hosted
    /// `main` stores at `argv[argc]` is outside this count.
    ///
    /// # Safety
    ///
    /// When `argc >= 1` and `argv` is non-null, `argv` addresses `argc`
    /// pointers and each one is non-null and NUL-terminated for this call.
    /// A null slot returns [`None`] and is not dereferenced.
    pub(crate) unsafe fn from_narrow_argv(argc: c_int, argv: *const *const c_char) -> Option<Self> {
        if argc < 1 || argv.is_null() {
            return None;
        }
        let count = usize::try_from(argc).ok()?;
        // SAFETY: the caller's contract: `argv` addresses `argc` pointers.
        let slots = unsafe { crate::legacy_util::slice_from_typed_ptr(argv, count) }?;
        let mut args = reserve_one_slot_per_pointer(count)?;
        for &slot in slots {
            if slot.is_null() {
                return None;
            }
            // SAFETY: the caller's contract: non-null and NUL-terminated.
            let argument = unsafe { CStr::from_ptr(slot) };
            args.push(os_string_from_narrow(argument)?);
        }
        Self::from_os_strings(args)
    }

    /// An argument vector the caller already holds.
    ///
    /// [`None`] when `args` is empty. Windows [`Self::from_process_entry`]
    /// collects `std::env::args_os` here, which is `GetCommandLineW`. The
    /// Rust process entry will do the same on every platform; that entry
    /// is the FOLLOWUPS row under DC-Q13.
    pub(crate) fn from_os_strings(args: Vec<OsString>) -> Option<Self> {
        if args.is_empty() {
            None
        } else {
            Some(Self { args })
        }
    }

    /// The program name and the arguments, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[OsString] {
        &self.args
    }
}

/// One `OsString` per pointer the caller addressed. The pointer array is
/// the backing the slice bound already accepted, so the reserve cannot
/// outgrow it.
fn reserve_one_slot_per_pointer(count: usize) -> Option<Vec<OsString>> {
    let stride = std::mem::size_of::<*const c_char>();
    let backing = count.checked_mul(stride)?;
    crate::legacy_util::bounded_capacity(count, stride, backing)
}

/// One narrow argument.
///
/// Unix keeps every byte, so that arm cannot fail. Windows decodes the
/// active code page and returns [`None`] for a byte that page cannot
/// represent. Any other target accepts the argument only when it is
/// Unicode: a replacement character would be a different argument. The
/// `Option` is that shared return; the Unix body is wrapped so the caller
/// has one `?`.
#[cfg_attr(unix, allow(clippy::unnecessary_wraps))]
fn os_string_from_narrow(argument: &CStr) -> Option<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Some(OsString::from_vec(argument.to_bytes().to_vec()))
    }
    // The active code page is the encoding of a Windows `char**`. One
    // UTF-16 unit per source byte is the ceiling: a character is at least
    // one byte there, and a longer result is not reserved.
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Globalization::{
            MultiByteToWideChar, CP_ACP, MB_ERR_INVALID_CHARS,
        };

        let bytes = argument.to_bytes();
        if bytes.is_empty() {
            return Some(OsString::new());
        }
        let byte_len = i32::try_from(bytes.len()).ok()?;
        // SAFETY: `bytes` is a live slice. A null destination and a zero
        // capacity ask for the length and write nothing.
        let needed = unsafe {
            MultiByteToWideChar(
                CP_ACP,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                byte_len,
                std::ptr::null_mut(),
                0,
            )
        };
        if needed <= 0 {
            return None;
        }
        let wide_len = usize::try_from(needed).ok()?;
        if wide_len > bytes.len() {
            return None;
        }
        let unit = std::mem::size_of::<u16>();
        let wide_bytes = wide_len.checked_mul(unit)?;
        let mut wide: Vec<u16> = crate::legacy_util::bounded_capacity(wide_len, unit, wide_bytes)?;
        wide.resize(wide_len, 0);
        // SAFETY: `wide` holds `wide_len` units. The call writes that many
        // or fails.
        let wrote = unsafe {
            MultiByteToWideChar(
                CP_ACP,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                byte_len,
                wide.as_mut_ptr(),
                needed,
            )
        };
        if wrote != needed {
            return None;
        }
        Some(OsString::from_wide(&wide))
    }
    #[cfg(not(any(unix, windows)))]
    {
        argument.to_str().ok().map(OsString::from)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn an_empty_or_null_vector_is_not_a_value() {
        assert!(ArgumentVector::from_os_strings(Vec::new()).is_none());
        assert!(unsafe { ArgumentVector::from_narrow_argv(0, std::ptr::null()) }.is_none());
        assert!(unsafe { ArgumentVector::from_narrow_argv(-1, std::ptr::null()) }.is_none());
        assert!(unsafe { ArgumentVector::from_narrow_argv(1, std::ptr::null()) }.is_none());
    }

    /// The hole sits after the program name, with a real argument after
    /// it. A shorter vector would be `Some` of the prefix. The count is
    /// the length, so the hole is `None` and the tail is not returned.
    #[test]
    fn a_null_slot_is_not_a_shorter_vector() {
        let program = CString::new("shekyld").unwrap();
        let network = CString::new("--network").unwrap();
        let name = CString::new("testnet").unwrap();
        let hole = [
            program.as_ptr(),
            network.as_ptr(),
            std::ptr::null(),
            name.as_ptr(),
        ];
        assert!(unsafe { ArgumentVector::from_narrow_argv(4, hole.as_ptr()) }.is_none());

        let first = [std::ptr::null(), network.as_ptr()];
        assert!(unsafe { ArgumentVector::from_narrow_argv(2, first.as_ptr()) }.is_none());

        let whole = [program.as_ptr(), network.as_ptr(), name.as_ptr()];
        let got = unsafe { ArgumentVector::from_narrow_argv(3, whole.as_ptr()) }.unwrap();
        assert_eq!(got.as_slice().len(), 3);
    }

    /// Lossy decoding would turn `0xff` into U+FFFD and this comparison
    /// would fail. The parser then refuses the byte (IG-Q2).
    #[cfg(unix)]
    #[test]
    fn a_narrow_argument_keeps_a_non_utf8_byte() {
        use std::os::unix::ffi::OsStrExt;
        let program = CString::new("shekyld").unwrap();
        let bad = CString::new(vec![b'-', b'-', 0xff]).unwrap();
        let ptrs = [program.as_ptr(), bad.as_ptr()];
        let got = unsafe { ArgumentVector::from_process_entry(2, ptrs.as_ptr()) }.unwrap();
        assert_eq!(got.as_slice()[1].as_bytes(), &[b'-', b'-', 0xff]);
    }
}
