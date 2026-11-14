// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! "This computer"'s second failure on Windows (`RPC_CHANNEL.md` RT-15):
//! a rendezvous that names a pipe failing the peer check is a security
//! failure, reported as one, and dialled once. GS-C3 test 7.
//!
//! The pipe is this account's, in this sign-in session, with a Low
//! integrity label, which the peer check refuses (below Medium, WP-D4):
//! the one property a process of the same account can give a pipe that the
//! check must refuse. The record names it as a daemon would. A second
//! instance waits behind the first, so a retry would be a second
//! connection, and the test counts them.

#![cfg(windows)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use shekyl_network::Network;
use shekyl_rpc_channel::rendezvous::{Record, PIPE_PREFIX};
use shekyl_rpc_channel::Instance;
use shekyl_rpc_transport::local::{LocalFault, LocalTarget};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// An owner-only descriptor with a Low mandatory label, freed on drop.
struct LowLabelled {
    psd: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl LowLabelled {
    fn new() -> Self {
        let me = shekyl_win_sec::current_user_sid().expect("this account's SID");
        let sddl = format!("D:P(A;;GA;;;{})S:(ML;;NW;;;LW)", me.as_str());
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; the callee
        // allocates `psd`, which `Drop` frees once.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut psd,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "the descriptor {sddl} converts");
        Self {
            psd,
            attributes: SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).expect("fits"),
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            },
        }
    }

    fn create(&mut self, name: &str, first: bool) -> NamedPipeServer {
        // SAFETY: the attributes and the descriptor they point at live as
        // long as `self`, which outlives the call.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .create_with_security_attributes_raw(
                    name,
                    (&raw mut self.attributes).cast::<std::ffi::c_void>(),
                )
        }
        .expect("the pipe")
    }
}

impl Drop for LowLabelled {
    fn drop(&mut self) {
        // SAFETY: `psd` came from the conversion and is freed once.
        unsafe { LocalFree(self.psd.cast()) };
    }
}

/// **A pipe that fails the peer check is the wrong thing there, and the
/// client does not retry it.** Red edit: map `DialError::Refused` to
/// `LocalFault::Stale` in `local::dial`, and the fault is not a security
/// failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_failing_the_peer_check_is_a_security_failure_dialled_once() {
    let dir = tempfile::tempdir().expect("a directory");
    let target = LocalTarget::resolve(Network::Regtest, &Instance::Default, Some(dir.path()))
        .expect("a named directory");
    let pipe = format!("{PIPE_PREFIX}{:032x}", u128::from(std::process::id()));
    let session = shekyl_win_sec::current_logon_sid().expect("this sign-in session");
    std::fs::write(
        target.path(),
        Record {
            pipe: pipe.clone(),
            session: session.as_str().to_owned(),
        }
        .bytes(),
    )
    .expect("the record");

    let mut descriptor = LowLabelled::new();
    let first = descriptor.create(&pipe, true);
    let behind = descriptor.create(&pipe, false);
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&connections);
    let server = tokio::spawn(async move {
        for instance in [first, behind] {
            if instance.connect().await.is_ok() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    let dialled = tokio::task::spawn_blocking(move || target.dial())
        .await
        .expect("the dial's task");
    let Err(fault) = dialled else {
        panic!("the client accepted a pipe below Medium integrity")
    };
    assert!(
        matches!(fault, LocalFault::PeerCheck(_)),
        "a failed peer check is the wrong thing there: {fault:?}"
    );
    assert!(fault.is_security_failure());
    assert!(fault.to_string().contains("Not connecting"), "{fault}");

    // Room for a retry to arrive at the instance waiting behind.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "the client dialled again after the peer check refused"
    );
    server.abort();
}
