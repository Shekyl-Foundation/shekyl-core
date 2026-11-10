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

pub use crate::methods::Policy;
use crate::schema::{Schema, Shape};

/// One method of the daemon's RPC.
pub trait RpcMethod {
    /// The name on the wire: the method's path, `_`-joined.
    const NAME: &'static str;
    /// Who may call it (`RPC_CHANNEL.md` §6.1).
    const POLICY: Policy;
    /// Its `params`: a named object, or `()` for none.
    type Request: serde::Serialize + serde::de::DeserializeOwned + Schema;
    /// Its `result`.
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

/// List every method once.
///
/// Each entry is `Type = "name": Request => Reply, policy;`. The macro
/// writes the unit type and its [`RpcMethod`], the identifier enum `$id`
/// with one variant for each method, and the table `$table`.
///
/// ```
/// use shekyl_rpc_types::method::{Policy, RpcMethod};
/// shekyl_rpc_types::rpc_methods! {
///     id Id; table TABLE;
///     /// The version read.
///     Version = "version": () => u32, Policy::Endpoint;
/// }
/// assert_eq!(Id::of("version"), Some(Id::Version));
/// assert_eq!(TABLE.len(), 1);
/// assert_eq!(<Version as RpcMethod>::NAME, "version");
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
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc_grants::Grant;

    crate::wire_object! {
        ["chain"]
        pub struct Tip {
            pub height: u64,
        }
    }

    crate::rpc_methods! {
        id Id; table TABLE;
        /// The version read.
        Version = "version": () => u32, Policy::Grant(Grant::Health);
        /// The tip.
        ChainHeight = "chain_height": () => Tip, Policy::Grant(Grant::Chain);
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
