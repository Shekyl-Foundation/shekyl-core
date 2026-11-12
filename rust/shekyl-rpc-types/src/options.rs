// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A configuration refusal (`RPC_CHANNEL.md` §6.4, RT-O25): what
//! `option_set` carries in its error's `data`, one element for each value
//! the table refused.

use serde::{Deserialize, Serialize};

/// One IG-11 diagnostic about one option: its stable code, the option it
/// is about, where the refused value came from, its named parameters
/// (IG-F20: a map), and the one renderer's message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    /// The stable code, such as `config.value.range`.
    pub code: String,
    /// The option the refusal is about; `null` when it is about none.
    pub option: crate::nullable::Nullable<String>,
    /// Where the refused value came from: `runtime` here.
    pub source: String,
    /// The named facts the message is built from.
    pub parameter: std::collections::BTreeMap<String, String>,
    /// What was wrong and what to do, as the startup parse would print it.
    pub message: String,
}
