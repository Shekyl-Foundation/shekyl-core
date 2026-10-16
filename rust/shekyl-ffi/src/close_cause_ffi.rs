// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The close causes' names for the C side's log lines, from the one table
//! in `shekyl-transport-layer` (`cause.rs`). The C++ kept its own switch of
//! names; a kind added in Rust was then "unknown" in every C++ log line
//! until someone remembered the switch.

use std::ffi::c_char;

use shekyl_transport_layer::CloseKind;

/// The name of close kind `kind`: `"none"` for 0, `"unknown"` for a code
/// not in the table. Static and NUL-terminated; the caller never frees it.
#[no_mangle]
pub extern "C" fn shekyl_close_kind_name(kind: u8) -> *const c_char {
    let name = match CloseKind::from_code(kind) {
        Some(kind) => kind.name_nul(),
        None if kind == 0 => "none\0",
        None => "unknown\0",
    };
    name.as_ptr().cast::<c_char>()
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    fn name(kind: u8) -> String {
        // SAFETY: the export returns a static NUL-terminated string.
        unsafe { CStr::from_ptr(shekyl_close_kind_name(kind)) }
            .to_str()
            .expect("utf-8")
            .to_owned()
    }

    #[test]
    fn every_kind_is_named_from_the_table() {
        for kind in CloseKind::ALL {
            assert_eq!(name(kind.code()), format!("{kind:?}"));
        }
        assert_eq!(name(0), "none");
        assert_eq!(name(255), "unknown");
        assert_eq!(name(CloseKind::ProxyUnavailable.code()), "ProxyUnavailable");
    }
}
