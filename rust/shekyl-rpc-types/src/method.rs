// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A method is a type (`RPC_WIRE.md` RW-Q7).
//!
//! Each method the daemon serves is one type implementing [`RpcMethod`]:
//! its name, its request, its reply and who may call it. One
//! [`rpc_methods!`](crate::rpc_methods) invocation lists every method and
//! writes, from that one list:
//!
//! - the types themselves, which a client names to call a method
//!   (`client.call::<ChainHeight>(…)`) and a test names to speak of one;
//! - the table of [`Row`]s, which the grant check, the schema
//!   ([`crate::schema`]) and the generated documents read;
//! - an identifier enum, which the server's dispatch matches. The match
//!   has no wildcard arm, so a row nothing serves does not compile, and a
//!   name reaches dispatch only by being a row.
//!
//! A method's name is its glossary path joined with `_` (RW-Q9), and it is
//! written once, in that invocation. No other string in the tree spells
//! it.

pub use shekyl_rpc_grants::{Grant, GrantSet, Preset};

/// Who may call a method (`RPC_CHANNEL.md` §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// A connection holding this grant.
    Grant(Grant),
    /// Host-only data (RT-O9.3): the host's administrator only, whatever a
    /// key's ceiling.
    HostOnly,
    /// An armed test lever (RT-O9.2): the host's administrator only, and only
    /// while the daemon runs with its armed-lever switch on.
    Armed,
    /// Every authenticated caller, whatever its grant: the version read
    /// (`RPC_WIRE.md` RW-Q6), which a client makes before it trusts
    /// anything else, so a key holding `submit` alone can still run the
    /// skew check. Never served before authentication (`RPC_CHANNEL.md`
    /// §4.3).
    Authenticated,
    /// The JSON-RPC endpoint itself: it serves any connection, and each
    /// method on it carries its own policy.
    Endpoint,
}

/// A bounded caller is every caller but the host's administrator (§6.3).
///
/// Host and bounded are one fact: the host is unbounded, and a connection
/// whose ceiling is every grant is still bounded. Gates read this, not a
/// second spelling of `!host`.
#[must_use]
pub const fn caller_bounded(host: bool) -> bool {
    !host
}

/// Proof that an armed lever's row was checked against the node's
/// armed-lever switch. Only [`admit_armed`] mints one, so an armed handler
/// cannot run unchecked.
#[derive(Debug)]
pub struct Armed(());

/// The diagnostic an armed lever carries when the switch is off.
pub const UNARMED: &str = "grant.unarmed";

/// Admit a call of `row` under the armed-lever switch.
///
/// A row that is not armed always passes. An armed row passes only when
/// the node was started with the switch on. The HTTP gate and the
/// in-process console both mint the token here; the handlers that still
/// run in process consume it.
///
/// # Errors
///
/// [`crate::errors::ErrorClass::OutsideTheGrant`] when `row` is armed and
/// `switch_on` is false, whatever the caller's other grants.
pub fn admit_armed(row: &Row, switch_on: bool) -> Result<Armed, crate::errors::RpcError> {
    use crate::errors::{Diagnostic, ErrorClass, RpcError};
    if row.armed() && !switch_on {
        return Err(RpcError::new(
            ErrorClass::OutsideTheGrant,
            Diagnostic::new(
                UNARMED,
                format!(
                    "{} is an armed test lever; start the node with dev-rpc to serve it",
                    row.name
                ),
            )
            .param("method", row.name),
        ));
    }
    Ok(Armed(()))
}

use crate::schema::{Schema, Shape};

/// One method of the daemon's RPC.
pub trait RpcMethod {
    /// The name on the wire: the method's path, `_`-joined.
    const NAME: &'static str;
    /// Who may call it (`RPC_CHANNEL.md` §6.1).
    const POLICY: Policy;
    /// Its `params`: a named object, or [`NoParams`](crate::kinds::NoParams).
    type Request: serde::Serialize + serde::de::DeserializeOwned + Schema;
    /// Its `result`; [`Done`](crate::kinds::Done) when success is all it says.
    type Reply: serde::Serialize + serde::de::DeserializeOwned + Schema;

    /// The words a person types for this method: its path, spaced.
    ///
    /// Exact, because a term never contains `_` (IG-1).
    #[must_use]
    fn words() -> String {
        Self::NAME.replace('_', " ")
    }
}

/// One row of the method table: a method's facts as data.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    /// The name on the wire.
    pub name: &'static str,
    /// Who may call it.
    pub policy: Policy,
    /// The request's shape.
    pub request: fn() -> Shape,
    /// The reply's shape.
    pub reply: fn() -> Shape,
}

impl Row {
    /// The row of method `M`.
    #[must_use]
    pub const fn of<M: RpcMethod>() -> Self {
        Self {
            name: M::NAME,
            policy: M::POLICY,
            request: <M::Request as Schema>::shape,
            reply: <M::Reply as Schema>::shape,
        }
    }

    /// Whether this row is an armed test lever.
    #[must_use]
    pub const fn armed(&self) -> bool {
        matches!(self.policy, Policy::Armed)
    }
}

const fn name_ok(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        let term_start = bytes[i - 1] == b'_';
        let ok = if b == b'_' {
            // No empty term: not doubled, and not last.
            !term_start && i + 1 < bytes.len()
        } else if term_start {
            b.is_ascii_lowercase()
        } else {
            b.is_ascii_lowercase() || b.is_ascii_digit()
        };
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

/// Refuse, at compile time, a name that is not a `_`-joined path of
/// `[a-z][a-z0-9]*` terms (IG-1). `stringify!(r#type)` is `r#type`, which
/// this refuses.
///
/// # Panics
///
/// In a const context, which fails the build.
pub const fn assert_name(name: &str) {
    assert!(
        name_ok(name),
        "a wire name is lowercase terms joined with `_` (IG-1)"
    );
}

const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Refuse, at compile time, a table with a malformed name or with one name
/// in two rows. A repeated name would otherwise be an unreachable match
/// arm, which only warns.
///
/// # Panics
///
/// In a const context, which fails the build.
pub const fn assert_table(rows: &[Row]) {
    let mut i = 0;
    while i < rows.len() {
        assert_name(rows[i].name);
        let mut j = i + 1;
        while j < rows.len() {
            assert!(
                !same(rows[i].name, rows[j].name),
                "one method name is in two rows of the table"
            );
            j += 1;
        }
        i += 1;
    }
}

/// List every method once.
///
/// Each entry is `Type = "name": Request => Reply, policy;`. The macro
/// writes the unit type and its [`RpcMethod`], the identifier enum `$id`
/// with one variant for each method, and the table `$table`.
///
/// ```
/// use shekyl_rpc_types::kinds::{Integer, NoParams};
/// use shekyl_rpc_types::method::{Policy, RpcMethod};
/// shekyl_rpc_types::rpc_methods! {
///     id Id; table TABLE;
///     /// The version read.
///     Version = "version": NoParams => Integer, Policy::Authenticated;
/// }
/// assert_eq!(Id::of("version"), Some(Id::Version));
/// assert_eq!(TABLE.len(), 1);
/// assert_eq!(<Version as RpcMethod>::NAME, "version");
/// ```
///
/// One name in two rows does not compile:
///
/// ```compile_fail
/// use shekyl_rpc_types::kinds::{Integer, NoParams};
/// use shekyl_rpc_types::method::Policy;
/// shekyl_rpc_types::rpc_methods! {
///     id Id; table TABLE;
///     Version = "version": NoParams => Integer, Policy::Authenticated;
///     Again = "version": NoParams => Integer, Policy::Authenticated;
/// }
/// ```
///
/// Nor does a name that is not a `_`-joined path:
///
/// ```compile_fail
/// use shekyl_rpc_types::kinds::{Integer, NoParams};
/// use shekyl_rpc_types::method::Policy;
/// shekyl_rpc_types::rpc_methods! {
///     id Id; table TABLE;
///     Version = "get-version": NoParams => Integer, Policy::Authenticated;
/// }
/// ```
#[macro_export]
macro_rules! rpc_methods {
    (
        id $id:ident; table $table:ident;
        $(
            $(#[$meta:meta])*
            $ty:ident = $name:literal : $request:ty => $reply:ty, $policy:expr;
        )+
    ) => {
        $(
            $(#[$meta])*
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct $ty;

            impl $crate::method::RpcMethod for $ty {
                const NAME: &'static str = $name;
                const POLICY: $crate::method::Policy = $policy;
                type Request = $request;
                type Reply = $reply;
            }
        )+

        /// Which method a call names. Dispatch matches this with no
        /// wildcard arm.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $id {
            $(
                #[doc = concat!("`", $name, "`.")]
                $ty,
            )+
        }

        impl $id {
            /// Every method, in table order.
            pub const ALL: &'static [Self] = &[$(Self::$ty),+];

            /// The method `name` names, if it names one.
            #[must_use]
            pub fn of(name: &str) -> ::core::option::Option<Self> {
                match name {
                    $($name => ::core::option::Option::Some(Self::$ty),)+
                    _ => ::core::option::Option::None,
                }
            }

            /// The method's row.
            #[must_use]
            pub const fn row(self) -> &'static $crate::method::Row {
                &$table[self as usize]
            }

            /// The method's name on the wire.
            #[must_use]
            pub const fn name(self) -> &'static str {
                self.row().name
            }
        }

        /// The method table: one row for each method, in the order listed.
        pub const $table: &[$crate::method::Row] = &[
            $($crate::method::Row::of::<$ty>()),+
        ];

        const _: () = $crate::method::assert_table($table);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kinds::{Integer, NoParams};
    use shekyl_rpc_grants::Grant;

    crate::wire_object! {
        ["chain"]
        pub struct Tip {
            pub height: crate::kinds::Height,
        }
    }

    crate::rpc_methods! {
        id Id; table TABLE;
        /// The version read.
        Version = "version": NoParams => Integer, Policy::Authenticated;
        /// The tip.
        ChainHeight = "chain_height": NoParams => Tip, Policy::Grant(Grant::Chain);
        /// A lever.
        DevChainPop = "dev_chain_pop": Tip => Tip, Policy::Armed;
    }

    /// The identifier, the type and the row are one method: a name finds
    /// its identifier, the identifier its row, and the row is the type's.
    /// Red edit: reorder the table against the enum in the macro.
    #[test]
    fn a_name_an_identifier_and_a_row_are_one_method() {
        assert_eq!(Id::ALL.len(), TABLE.len());
        for id in Id::ALL {
            assert_eq!(Id::of(id.name()), Some(*id));
        }
        assert_eq!(Id::ChainHeight.name(), <ChainHeight as RpcMethod>::NAME);
        assert_eq!(Id::ChainHeight.row().policy, Policy::Grant(Grant::Chain));
        assert!(Id::DevChainPop.row().armed());
        assert!(!Id::Version.row().armed());
        assert_eq!(Id::of("get_height"), None);
    }

    /// The checks the macro runs at compile time, as functions. A second
    /// row named `version`, or a name `r#type`, `Chain`, `chain__height`
    /// or `chain_`, fails the build.
    #[test]
    fn a_malformed_or_repeated_name_is_refused() {
        for good in ["version", "chain_height", "block_header_list", "p2p_stats"] {
            assert!(name_ok(good), "{good}");
        }
        for bad in [
            "",
            "r#type",
            "Chain",
            "chain__height",
            "chain_",
            "_chain",
            "2fa",
            "chain_2x",
            "get-info",
        ] {
            assert!(!name_ok(bad), "{bad}");
        }
        assert!(same("version", "version"));
        assert!(!same("version", "versions"));
        let twice = std::panic::catch_unwind(|| {
            assert_table(&[Row::of::<Version>(), Row::of::<Version>()]);
        });
        assert!(twice.is_err());
        assert_table(TABLE);
    }

    /// The version read is callable by every authenticated caller,
    /// whatever its grant (RW-Q6): a `submit`-only key runs the skew
    /// check. Red edit: give `Version` the `health` grant.
    #[test]
    fn the_version_read_is_under_no_grant() {
        assert_eq!(Id::Version.row().policy, Policy::Authenticated);
    }

    #[test]
    fn a_methods_words_are_its_path() {
        assert_eq!(ChainHeight::words(), "chain height");
        assert_eq!(DevChainPop::words(), "dev chain pop");
    }

    /// The schema reads a method's parameters and fields through its row.
    #[test]
    fn the_schema_reaches_every_name_through_the_table() {
        let walked: Vec<String> = crate::schema::names(TABLE)
            .into_iter()
            .map(|name| {
                format!(
                    "{} {} [{}] {}",
                    name.method,
                    name.kind.word(),
                    name.holder,
                    name.name
                )
            })
            .collect();
        assert_eq!(
            walked,
            [
                "version method [] version",
                "chain_height method [] chain_height",
                "chain_height field [chain] height",
                "dev_chain_pop method [] dev_chain_pop",
                "dev_chain_pop parameter [chain] height",
                "dev_chain_pop field [chain] height",
            ]
        );
    }
}
