// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The input grammar's shared crate (`docs/design/INPUT_GRAMMAR.md` IG-15).
//!
//! Every binary builds its option table from this crate: the [`Table`] and
//! its [`Row`]s (IG-9), the value [`Kind`]s and their parsers (IG-6), the
//! readers of the two surfaces ([`read_cli`], [`read_file`]), and the typed
//! [`Diagnostic`] with its one renderer (IG-11). Names, kinds and defaults
//! are the grammar's; a binary states them in its table, never here.
//!
//! What is not here: precedence between the surfaces, the file's permission
//! checks, and the typed sections a binary's owners take. Those are each
//! binary's (`shekyl-daemon-config` for the daemon).

#![deny(unsafe_code)]

pub mod diagnostic;
pub mod input;
pub mod kind;
pub mod table;

pub use diagnostic::{Code, Diagnostic, Fault, Source};
pub use input::{read_cli, read_file, Cli, Given};
pub use kind::{
    is_global_unicast, Dimension, EndpointRule, KeyRule, Kind, PeerEndpoint, PeerRule, Secret,
    Value,
};
pub use table::{lexical, Default, Grant, Row, Surface, Table, Visibility};
