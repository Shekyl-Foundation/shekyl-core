// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's side of the RPC channel (`docs/design/RPC_CHANNEL.md` §4,
//! §5, §6.2; RT-W10 step 4).
//!
//! - **The key** ([`files`]): the daemon's static identity and its public
//!   bundle, in the network's data directory, generated on the first start
//!   and readable by the daemon's account alone (RT-O34).
//! - **The enrolled set** ([`store`]): each client's fingerprint and its
//!   ceiling as expanded grants, changed only through the enrollment
//!   methods (IG-Q87). A service also holds a console key, the host
//!   administrator's credential, which is not an enrollment (§5).
//! - **Live sessions** ([`sessions`]), indexed by fingerprint, so a removal
//!   or a lowered ceiling closes them at once.
//! - **The listener** ([`listener`]): the handshake under its deadlines and
//!   budget, admission by fingerprint, message 4 carrying the client's
//!   ceiling (RT-O30, RT-O31), and the record stream into the router, each
//!   request stamped with the connection's effective grant (RT-O32).

mod console;
pub mod console_leg;
pub mod files;
pub mod listener;
mod message;
pub mod rendezvous;
pub mod sessions;
pub mod store;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use shekyl_rpc_channel::budget::HandshakeBudget;
use shekyl_rpc_channel::handshake::StaticKeypair;
use shekyl_rpc_channel::NetworkId;
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::kinds::Bytes;
use shekyl_rpc_types::wire::rpc::{self as wire_rpc, CeilingWord};

use crate::authority::Authority;
use crate::run::StartFault;
use sessions::Sessions;
use store::{Enroller, Enrollment, Store, StoreError};

/// The enrollment methods' diagnostic codes.
pub mod codes {
    /// `rpc_client_add` on a fingerprint already enrolled; `set` changes it.
    pub const ENROLLED: &str = "rpc.client.enrolled";
    /// `rpc_client_set` or `rpc_client_remove` on a fingerprint not
    /// enrolled; `add` enrolls it.
    pub const NOT_ENROLLED: &str = "rpc.client.not-enrolled";
    /// A ceiling, given or held, beyond the caller's own grant (RT-O9.1).
    pub const BEYOND_CALLER: &str = "rpc.client.beyond-caller";
    /// The console key, which is not an enrollment (§5).
    pub const CONSOLE: &str = "rpc.client.console";
    /// Enrollment on a plaintext listener. It is served on the owner's
    /// socket and over the channel (§5).
    pub const PLAINTEXT: &str = "rpc.client.plaintext";
    /// The enrolled set could not be read or written.
    pub const STORE: &str = "rpc.client.store";
    /// A `tx_submit` over the channel whose body was not padded to the
    /// submission's fixed size (RT-O28).
    pub const UNPADDED: &str = "submit.unpadded";
}

/// What the channel listens with and where its files are.
#[derive(Clone, Debug)]
pub struct ChannelSetup {
    /// The network's data directory, under the daemon's exclusive lock.
    pub data_dir: PathBuf,
    /// The network id the handshake's prologue binds.
    pub network_id: NetworkId,
    /// Whether this is the machine's service instance, which has a console
    /// key (§5).
    pub service: bool,
    /// A service's rendezvous directory, checked by the walk; `None` for a
    /// daemon run as its user. A service started with `rpc-listen`
    /// publishes its machine-wide rendezvous record there (§7.1).
    pub service_rendezvous: Option<PathBuf>,
    /// The instance, whose name the record's file name hashes with the
    /// network id (RT-O10).
    pub instance: shekyl_rpc_rendezvous::Instance,
}

/// A channel connection's caller, stamped on each of its requests beside
/// its [`Authority`]: who the authenticated client is, and the shapes of
/// the records the connection read. Absent on the plaintext listeners and
/// the owner's leg, whose caller is the host's administrator.
#[derive(Clone, Debug)]
pub struct ChannelCall {
    /// The authenticated client's fingerprint.
    pub client: [u8; 32],
    /// The client is the console key.
    pub console: bool,
    /// The records this connection read, and whether the HTTP message just
    /// finished is exactly one submission (RT-O28). `tx_submit` reads the
    /// message's claim, not the last record on the connection.
    pub shape: shekyl_rpc_stream::InboundShape,
}

/// Who is enrolling. A channel caller is that caller. The owner's socket
/// is the host. A plaintext listener is refused: it is reachable by any
/// local account until RT-W12, and an enrollment made there would outlive
/// it (§5, RT-O33).
///
/// # Errors
///
/// [`codes::PLAINTEXT`] when the caller is a plaintext listener.
pub fn enrollment_caller(call: Option<&ChannelCall>, owner: bool) -> Result<Enroller, RpcError> {
    if let Some(call) = call {
        return Ok(call.enroller());
    }
    if owner {
        return Ok(Enroller::Host);
    }
    Err(RpcError::new(
        ErrorClass::RefusedByMethod,
        Diagnostic::new(
            codes::PLAINTEXT,
            "enrollment is served on the owner's socket and over the channel".to_owned(),
        ),
    ))
}

impl ChannelCall {
    /// Who enrolls, as the enrolled set records it.
    #[must_use]
    pub fn enroller(&self) -> Enroller {
        if self.console {
            Enroller::Console
        } else {
            Enroller::Client(self.client)
        }
    }
}

/// What a fingerprint is admitted as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// The console key: every grant and the host's classes (§5).
    Console,
    /// An enrolled client, under its ceiling.
    Client(GrantSet),
}

impl Admitted {
    /// The ceiling message 4 carries.
    #[must_use]
    pub fn ceiling(self) -> GrantSet {
        match self {
            Self::Console => GrantSet::ALL,
            Self::Client(ceiling) => ceiling,
        }
    }
}

/// The channel's state, one per daemon.
pub struct Channel {
    pub(crate) key: StaticKeypair,
    pub(crate) network_id: NetworkId,
    pub(crate) store: Store,
    pub(crate) sessions: Arc<Sessions>,
    pub(crate) budget: HandshakeBudget,
    /// Where a service publishes its rendezvous record, when it listens.
    pub(crate) service_rendezvous: Option<shekyl_rpc_rendezvous::ServiceRecordAt>,
    /// A service's data directory, where its console leg is bound
    /// ([`console_leg`]); `None` for a daemon run as its user.
    pub(crate) console_dir: Option<PathBuf>,
}

impl Channel {
    /// Open the channel's state: read the key, or generate and write it on
    /// the first start; open the enrolled set; and for a service, make its
    /// console key on the first start. Called under the data directory's
    /// lock.
    ///
    /// # Errors
    ///
    /// [`StartFault::HeldOpen`] when another program held a staged file
    /// open past the wait; otherwise the refusal, in the operator's words.
    pub fn open(setup: &ChannelSetup) -> Result<Arc<Self>, StartFault> {
        let dir = &setup.data_dir;
        let key_path = dir.join(files::KEY_FILE);
        let key = match files::read_key(&key_path)? {
            Some(key) => key,
            None => {
                let key = StaticKeypair::generate()
                    .map_err(|e| format!("the RPC channel's key could not be made: {e}"))?;
                files::write_private(&key_path, &key.to_key_file())?;
                tracing::info!(
                    target: "global",
                    "the RPC channel's key was made at {}",
                    key_path.display()
                );
                key
            }
        };
        let bundle_path = dir.join(files::BUNDLE_FILE);
        let replaced =
            shekyl_os_account::private_file::replace_console(&bundle_path, &bundle(&key))
                .map_err(files::FileRefused::from)?;
        files::note_replaced(&bundle_path, &replaced);
        let store = Store::open(dir).map_err(|e| e.to_string())?;
        // The console key's file and its cell are one change. A start
        // finishes a commit the last process did not rename, and only then
        // makes a key when the service has none (§5).
        if setup.service {
            match console::reconcile(dir, &store)? {
                console::Reconcile::Consistent => {}
                console::Reconcile::Placed => tracing::info!(
                    target: "global",
                    "the service's console key is at {}",
                    dir.join(files::CONSOLE_KEY_FILE).display()
                ),
                console::Reconcile::Absent => {
                    let path = console::install(dir, &store, None)?;
                    tracing::info!(
                        target: "global",
                        "the service's console key was made at {}",
                        path.display()
                    );
                }
            }
        }
        // The console key's reset is logged at the next start (§5). The
        // note is committed with the fingerprint, so it is read after the
        // file is in place.
        if let Some(at) = store.take_console_reset().map_err(|e| e.to_string())? {
            tracing::warn!(
                target: "global",
                "the service's console key was replaced offline (at {at}, seconds since the \
                 Unix epoch); the previous console key no longer reaches this node"
            );
        }
        Ok(Arc::new(Self {
            key,
            network_id: setup.network_id,
            store,
            sessions: Arc::new(Sessions::default()),
            budget: HandshakeBudget::new(Instant::now()),
            service_rendezvous: service_record_at(setup),
            console_dir: setup.service.then(|| setup.data_dir.clone()),
        }))
    }

    /// What `fingerprint` is admitted as, if anything.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn admitted(&self, fingerprint: &[u8; 32]) -> Result<Option<Admitted>, StoreError> {
        if self.store.console()?.as_ref() == Some(fingerprint) {
            return Ok(Some(Admitted::Console));
        }
        Ok(self
            .store
            .get(fingerprint)?
            .map(|enrollment| Admitted::Client(enrollment.ceiling)))
    }

    /// `rpc_bundle_show`.
    #[must_use]
    pub fn bundle_show(&self) -> wire_rpc::Bundle {
        wire_rpc::Bundle {
            bundle: Bytes(bundle(&self.key)),
        }
    }

    /// `rpc_client_list`: the enrollments whose ceiling lies within the
    /// caller's grant; the others are absent (IG-Q87).
    ///
    /// # Errors
    ///
    /// The store's fault.
    pub fn client_list(&self, caller: Authority) -> Result<Vec<wire_rpc::Client>, RpcError> {
        Ok(self
            .store
            .list()
            .map_err(store_fault)?
            .into_iter()
            .filter(|(_, enrollment)| enrollment.ceiling.within(caller.grants()))
            .map(|(fingerprint, enrollment)| wire_rpc::Client {
                fingerprint: HashHex::from_bytes(fingerprint),
                ceiling: wire_rpc::grant_names(enrollment.ceiling),
            })
            .collect())
    }

    /// `rpc_client_add`: enroll a fingerprint not enrolled, under a ceiling
    /// within the caller's grant (RT-O9.1).
    ///
    /// # Errors
    ///
    /// Already enrolled, the console key, a ceiling beyond the caller, or
    /// the store's fault.
    pub fn client_add(
        &self,
        caller: Authority,
        by: Enroller,
        fingerprint: [u8; 32],
        ceiling: &[CeilingWord],
    ) -> Result<(), RpcError> {
        let ceiling = within_caller(caller, CeilingWord::expand(ceiling))?;
        self.not_console(&fingerprint)?;
        self.sessions.change(|_| {
            if self.store.get(&fingerprint).map_err(store_fault)?.is_some() {
                return Err(refused(
                    codes::ENROLLED,
                    "this client is already enrolled; `rpc client set` changes its ceiling",
                    &fingerprint,
                ));
            }
            self.store
                .put(
                    &fingerprint,
                    Enrollment {
                        ceiling,
                        enrolled_at: now(),
                        by,
                    },
                )
                .map_err(store_fault)
        })
    }

    /// `rpc_client_set`: change an enrolled ceiling. Both the new ceiling
    /// and the one it replaces lie within the caller's grant (RT-O9.1). A
    /// ceiling that loses a grant closes the fingerprint's sessions (§5).
    ///
    /// # Errors
    ///
    /// Not enrolled, the console key, a ceiling beyond the caller, or the
    /// store's fault.
    pub fn client_set(
        &self,
        caller: Authority,
        fingerprint: [u8; 32],
        ceiling: &[CeilingWord],
    ) -> Result<(), RpcError> {
        let ceiling = within_caller(caller, CeilingWord::expand(ceiling))?;
        self.not_console(&fingerprint)?;
        self.sessions.change(|changing| {
            let Some(held) = self.store.get(&fingerprint).map_err(store_fault)? else {
                return Err(not_enrolled(&fingerprint));
            };
            within_caller(caller, held.ceiling)?;
            self.store
                .put(&fingerprint, Enrollment { ceiling, ..held })
                .map_err(store_fault)?;
            if !held.ceiling.within(ceiling) {
                changing.close(&fingerprint);
            }
            Ok(())
        })
    }

    /// `rpc_client_remove`: revoke an enrollment within the caller's grant,
    /// and close every session the fingerprint holds (§5).
    ///
    /// # Errors
    ///
    /// Not enrolled, the console key, a ceiling beyond the caller, or the
    /// store's fault.
    pub fn client_remove(&self, caller: Authority, fingerprint: [u8; 32]) -> Result<(), RpcError> {
        self.not_console(&fingerprint)?;
        self.sessions.change(|changing| {
            let Some(held) = self.store.get(&fingerprint).map_err(store_fault)? else {
                return Err(not_enrolled(&fingerprint));
            };
            within_caller(caller, held.ceiling)?;
            self.store.remove(&fingerprint).map_err(store_fault)?;
            changing.close(&fingerprint);
            Ok(())
        })
    }

    fn not_console(&self, fingerprint: &[u8; 32]) -> Result<(), RpcError> {
        if self.store.console().map_err(store_fault)?.as_ref() == Some(fingerprint) {
            return Err(refused(
                codes::CONSOLE,
                "this is the console key, which is not an enrollment; `shekyld --rpc-console-key-reset` replaces it",
                fingerprint,
            ));
        }
        Ok(())
    }
}

/// `tx_submit` over the channel with a body that did not arrive as a
/// padded submission (RT-O28; pre-flight close-out F2).
#[must_use]
pub fn unpadded_submission() -> RpcError {
    RpcError::new(
        ErrorClass::BadParams,
        Diagnostic::new(
            codes::UNPADDED,
            "over the channel a transaction is sent as a padded submission of fixed size"
                .to_owned(),
        ),
    )
}

/// The read-only check of the channel's enrollment store in `data_dir`
/// ([`Store::check`]): a daemon runs it with its other stores' checks,
/// before it writes anything, so a start one of them refuses leaves the
/// directory as it found it.
///
/// # Errors
///
/// The refusal, in the operator's words ([`StartFault::Refused`]).
pub fn check_store(data_dir: &Path) -> Result<(), StartFault> {
    Store::check(data_dir).map_err(|e| StartFault::Refused(e.to_string()))
}

/// Replace a service's console key. The new private half, the fingerprint
/// and the reset note are one change ([`console::install`]): a crash leaves
/// a journal the next start finishes, or the previous key. The caller holds
/// the data directory's lock (IG-Q88, §5); no other enrollment is touched.
/// Returns where the private half was written.
///
/// # Errors
///
/// [`StartFault::HeldOpen`] when another program held the journal open past
/// the wait; otherwise the refusal, in the operator's words.
pub fn reset_console_key(data_dir: &Path) -> Result<PathBuf, StartFault> {
    let store = Store::open(data_dir).map_err(|e| e.to_string())?;
    Ok(console::install(data_dir, &store, Some(now()))?)
}

/// Where a service publishes its record: the file in the walk's checked
/// rendezvous directory on Linux, FreeBSD and macOS; on Windows the value
/// under `HKLM\SOFTWARE\Shekyl\Rendezvous` (Rick, 2026-11-18). `None` for a
/// daemon run as its user.
fn service_record_at(setup: &ChannelSetup) -> Option<shekyl_rpc_rendezvous::ServiceRecordAt> {
    #[cfg(windows)]
    {
        setup.service.then(|| {
            shekyl_rpc_rendezvous::ServiceRecordAt::registry(
                shekyl_win_sec::registry::RENDEZVOUS_KEY,
                &setup.network_id,
                &setup.instance,
            )
        })
    }
    #[cfg(not(windows))]
    {
        setup.service_rendezvous.as_deref().map(|dir| {
            shekyl_rpc_rendezvous::ServiceRecordAt::file(dir, &setup.network_id, &setup.instance)
        })
    }
}

/// The public bundle as it travels: the X25519 key, then the ML-KEM-768
/// encapsulation key.
pub(crate) fn bundle(key: &StaticKeypair) -> Vec<u8> {
    let mut out = key.public().x25519().to_vec();
    out.extend_from_slice(key.public().mlkem_ek());
    out
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn within_caller(caller: Authority, ceiling: GrantSet) -> Result<GrantSet, RpcError> {
    if ceiling.within(caller.grants()) {
        Ok(ceiling)
    } else {
        Err(RpcError::new(
            ErrorClass::OutsideTheGrant,
            Diagnostic::new(
                codes::BEYOND_CALLER,
                "a ceiling may not exceed the grant of the key that sets it or removes it"
                    .to_owned(),
            ),
        ))
    }
}

fn refused(code: &'static str, message: &str, fingerprint: &[u8; 32]) -> RpcError {
    RpcError::new(
        ErrorClass::RefusedByMethod,
        Diagnostic::new(code, message.to_owned()).param("fingerprint", hex::encode(fingerprint)),
    )
}

fn not_enrolled(fingerprint: &[u8; 32]) -> RpcError {
    refused(
        codes::NOT_ENROLLED,
        "this client is not enrolled; `rpc client add` enrolls it",
        fingerprint,
    )
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the `map_err` argument; the fault is read for its message"
)]
fn store_fault(e: StoreError) -> RpcError {
    RpcError::new(
        ErrorClass::StoreFault,
        Diagnostic::new(codes::STORE, e.to_string()),
    )
}
