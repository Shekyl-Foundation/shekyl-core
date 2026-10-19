// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Strict readers over a [`Resolved`](crate::resolve::Resolved).
//!
//! A row the table fills is present after resolve, and a derived default
//! the process uses is present after materialize. Absence of such a row,
//! and a value of the wrong [`Value`] arm, are faults: the reader records
//! them and returns [`Read::Unreadable`] so the build can keep collecting.
//! A row this build does not fill (`tor-file`, `clearnet-listen` while
//! clearnet is off, an unset development lever) may be absent. A keyword
//! the row admits (`unlimited`, `auto`) is that keyword, not a missing value.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;

use shekyl_options::{Code, Diagnostic, PeerEndpoint, Secret, Source, Value};

use crate::resolve::Resolved;

/// What a read found. `Unreadable` means a fault was already recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Read<T> {
    /// The row held a value of the arm this read asked for.
    Present(T),
    /// The row is not in the resolved set. Legal for a derived or unset row.
    Absent,
    /// The row was missing where the table fills it, or its value was the
    /// wrong arm. A fault is in the reader's list.
    Unreadable,
}

impl<T> Read<T> {
    /// The value when one was read. Absence and a fault are both "no value".
    pub(super) fn present(self) -> Option<T> {
        match self {
            Self::Present(value) => Some(value),
            Self::Absent | Self::Unreadable => None,
        }
    }
}

/// A rate row: a cap, the `unlimited` keyword, or a fault already recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RateBound {
    /// Bytes per second.
    Capped(u64),
    /// The row's `unlimited` keyword.
    Unlimited,
    /// A fault was recorded.
    Unreadable,
}

/// `mine-threads`: a count, the `auto` keyword, or a fault already recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ThreadCount {
    /// The operator chose a count.
    Counted(NonZeroU32),
    /// The row's `auto` keyword: the miner chooses.
    Auto,
    /// A fault was recorded.
    Unreadable,
}

pub(super) struct Reader<'a> {
    resolved: &'a Resolved,
    pub(super) faults: Vec<Diagnostic>,
}

impl<'a> Reader<'a> {
    pub(super) fn new(resolved: &'a Resolved) -> Self {
        Self {
            resolved,
            faults: Vec::new(),
        }
    }

    pub(super) fn source(&self, name: &str) -> Source {
        self.resolved
            .source(name)
            .cloned()
            .unwrap_or(Source::Default)
    }

    pub(super) fn positional(&self) -> &[String] {
        &self.resolved.positional
    }

    /// The operator set the row: not absent, and not the table's default.
    pub(super) fn given(&self, name: &str) -> bool {
        !matches!(self.resolved.source(name), None | Some(Source::Default))
    }

    pub(super) fn conflict(&mut self, name: &str, conflict: &str) {
        self.faults.push(
            Diagnostic::new(Code::ValueConflict, self.source(name))
                .option(name)
                .param("conflict", conflict),
        );
    }

    pub(super) fn requires(&mut self, name: &str, requires: &str) {
        self.faults.push(
            Diagnostic::new(Code::ValueRequires, self.source(name))
                .option(name)
                .param("requires", requires),
        );
    }

    fn syntax(&mut self, name: &str, value: &str, expected: &str) {
        self.faults.push(
            Diagnostic::new(Code::ValueSyntax, self.source(name))
                .option(name)
                .param("value", value)
                .param("expected", expected),
        );
    }

    fn range(&mut self, name: &str, value: &str, rule: &str) {
        self.faults.push(
            Diagnostic::new(Code::ValueRange, self.source(name))
                .option(name)
                .param("value", value)
                .param("rule", rule),
        );
    }

    pub(super) fn word_choice(&mut self, name: &str, value: &str, words: &str) {
        self.faults.push(
            Diagnostic::new(Code::ValueWord, self.source(name))
                .option(name)
                .param("value", value)
                .param("words", words),
        );
    }

    fn take(&self, name: &str) -> Option<&Value> {
        self.resolved.get(name)
    }

    /// A word the table fills. Absence and any other arm are faults.
    pub(super) fn required_word(&mut self, name: &str) -> Option<&'static str> {
        match self.take(name).cloned() {
            Some(Value::Word(word)) => Some(word),
            Some(other) => {
                self.syntax(name, &other.render(), "a word");
                None
            }
            None => {
                self.syntax(name, "absent", "a word");
                None
            }
        }
    }

    /// A word that may be absent. Another arm is a fault.
    pub(super) fn optional_word(&mut self, name: &str) -> Read<&'static str> {
        match self.take(name).cloned() {
            Some(Value::Word(word)) => Read::Present(word),
            Some(other) => {
                self.syntax(name, &other.render(), "a word");
                Read::Unreadable
            }
            None => Read::Absent,
        }
    }

    /// A byte count the table fills.
    pub(super) fn required_bytes(&mut self, name: &str) -> Option<u64> {
        match self.take(name).cloned() {
            Some(Value::Bytes(n)) => Some(n),
            Some(other) => {
                self.syntax(name, &other.render(), "a byte count");
                None
            }
            None => {
                self.syntax(name, "absent", "a byte count");
                None
            }
        }
    }

    /// An integer the table fills, in `1..=u32::MAX`. A wider integer is a
    /// range fault, not a silent one.
    pub(super) fn required_count(&mut self, name: &str) -> Option<NonZeroU32> {
        match self.take(name).cloned() {
            Some(Value::Integer(n)) => match u32::try_from(n).ok().and_then(NonZeroU32::new) {
                Some(count) => Some(count),
                None => {
                    self.range(
                        name,
                        &n.to_string(),
                        &format!("an integer from 1 to {}", u32::MAX),
                    );
                    None
                }
            },
            Some(other) => {
                self.syntax(name, &other.render(), "an integer");
                None
            }
            None => {
                self.syntax(name, "absent", "an integer");
                None
            }
        }
    }

    /// A development lever's integer. Absence is the lever left unset,
    /// including a lever the network gate skipped. Another arm is a fault.
    pub(super) fn dev_integer(&mut self, name: &str) -> Option<u64> {
        match self.take(name).cloned() {
            None => None,
            Some(Value::Integer(n)) => Some(n),
            Some(other) => {
                self.syntax(name, &other.render(), "an integer");
                None
            }
        }
    }

    /// A rate the table fills: a cap, or the word `unlimited`.
    pub(super) fn rate(&mut self, name: &str) -> RateBound {
        match self.take(name).cloned() {
            Some(Value::Rate(n)) => RateBound::Capped(n),
            Some(Value::Word("unlimited")) => RateBound::Unlimited,
            Some(other) => {
                self.syntax(name, &other.render(), "a rate or `unlimited`");
                RateBound::Unreadable
            }
            None => {
                self.syntax(name, "absent", "a rate or `unlimited`");
                RateBound::Unreadable
            }
        }
    }

    /// `mine-threads`: a count in `1..=u32::MAX`, or the word `auto`.
    pub(super) fn thread_count(&mut self, name: &str) -> ThreadCount {
        match self.take(name).cloned() {
            Some(Value::Word("auto")) => ThreadCount::Auto,
            Some(Value::Integer(n)) => match u32::try_from(n).ok().and_then(NonZeroU32::new) {
                Some(count) => ThreadCount::Counted(count),
                None => {
                    self.range(
                        name,
                        &n.to_string(),
                        &format!("an integer from 1 to {}, or `auto`", u32::MAX),
                    );
                    ThreadCount::Unreadable
                }
            },
            Some(other) => {
                self.syntax(name, &other.render(), "a count or `auto`");
                ThreadCount::Unreadable
            }
            None => {
                self.syntax(name, "absent", "a count or `auto`");
                ThreadCount::Unreadable
            }
        }
    }

    pub(super) fn optional_endpoint(&mut self, name: &str) -> Read<SocketAddr> {
        match self.take(name).cloned() {
            None => Read::Absent,
            Some(Value::Endpoint(endpoint)) => Read::Present(endpoint),
            Some(other) => {
                self.syntax(name, &other.render(), "an endpoint");
                Read::Unreadable
            }
        }
    }

    /// One half of an RFC 1929 pair: 1 to `max` bytes, the field RFC 1929
    /// carries. A refusal never shows the text.
    pub(super) fn socks_secret(&mut self, name: &str, max: usize) -> Read<Secret> {
        match self.take(name).cloned() {
            None => Read::Absent,
            Some(Value::Secret(secret)) if (1..=max).contains(&secret.expose().len()) => {
                Read::Present(secret)
            }
            Some(Value::Secret(_)) => {
                self.range(
                    name,
                    "(not shown)",
                    &format!("1 to {max} bytes, as RFC 1929 carries it"),
                );
                Read::Unreadable
            }
            Some(_) => {
                self.syntax(name, "(not shown)", "a secret");
                Read::Unreadable
            }
        }
    }

    pub(super) fn optional_path(&mut self, name: &str) -> Read<PathBuf> {
        match self.take(name).cloned() {
            None => Read::Absent,
            Some(Value::Path(path)) => Read::Present(path),
            Some(other) => {
                self.syntax(name, &other.render(), "a path");
                Read::Unreadable
            }
        }
    }

    /// Endpoints. `required` is a row the table fills with `none` (an empty
    /// list); a derived or unset list may be absent.
    pub(super) fn endpoint_list(&mut self, name: &str, required: bool) -> Vec<SocketAddr> {
        self.list(name, required, "an endpoint", |item| match item {
            Value::Endpoint(endpoint) => Some(*endpoint),
            _ => None,
        })
    }

    /// Peers. The table fills the row with `none`.
    pub(super) fn peer_list(&mut self, name: &str) -> Vec<PeerEndpoint> {
        self.list(name, true, "a peer", |item| match item {
            Value::Peer(peer) => Some(peer.clone()),
            _ => None,
        })
    }

    /// Origins. The table fills the row with `none`.
    pub(super) fn origin_list(&mut self, name: &str) -> Vec<String> {
        self.list(name, true, "an origin", |item| match item {
            Value::Origin(origin) => Some(origin.clone()),
            _ => None,
        })
    }

    fn list<T>(
        &mut self,
        name: &str,
        required: bool,
        item_expected: &str,
        take: impl Fn(&Value) -> Option<T>,
    ) -> Vec<T> {
        match self.take(name).cloned() {
            Some(Value::List(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in &items {
                    match take(item) {
                        Some(value) => out.push(value),
                        None => self.syntax(name, &item.render(), item_expected),
                    }
                }
                out
            }
            Some(other) => {
                self.syntax(
                    name,
                    &other.render(),
                    &format!("a list of {item_expected}s"),
                );
                Vec::new()
            }
            None if required => {
                self.syntax(name, "absent", &format!("a list of {item_expected}s"));
                Vec::new()
            }
            None => Vec::new(),
        }
    }

    /// Level words. The table fills the row with `none` (an empty map).
    pub(super) fn level_map(&mut self, name: &str) -> Vec<(String, &'static str)> {
        match self.take(name).cloned() {
            Some(Value::Map(map)) => self.level_entries(name, &map),
            Some(other) => {
                self.syntax(name, &other.render(), "a map of level words");
                Vec::new()
            }
            None => {
                self.syntax(name, "absent", "a map of level words");
                Vec::new()
            }
        }
    }

    fn level_entries(
        &mut self,
        name: &str,
        map: &BTreeMap<String, Value>,
    ) -> Vec<(String, &'static str)> {
        let mut out = Vec::with_capacity(map.len());
        for (key, value) in map {
            match value {
                Value::Word(word) if crate::LEVELS.contains(word) => out.push((key.clone(), *word)),
                Value::Word(word) => {
                    self.word_choice(name, word, "error, warn, info, debug, trace");
                }
                other => self.syntax(name, &other.render(), "a level word"),
            }
        }
        out
    }

    pub(super) fn command(&mut self, name: &str) -> Option<Vec<String>> {
        match self.take(name).cloned() {
            None => None,
            Some(Value::Command(args)) => Some(args),
            Some(other) => {
                self.syntax(name, &other.render(), "a command");
                None
            }
        }
    }

    /// An onion peer. Absence is "no onion". An IP peer is the wrong shape.
    pub(super) fn onion(&mut self, name: &str) -> Read<(String, u16)> {
        match self.take(name).cloned() {
            None => Read::Absent,
            Some(Value::Peer(PeerEndpoint::Onion { host, port })) => Read::Present((host, port)),
            Some(other) => {
                self.syntax(name, &other.render(), "an onion");
                Read::Unreadable
            }
        }
    }

    pub(super) fn address(&mut self, name: &str) -> Read<String> {
        match self.take(name).cloned() {
            None => Read::Absent,
            Some(Value::Address(text)) => Read::Present(text),
            Some(other) => {
                self.syntax(name, &other.render(), "an address");
                Read::Unreadable
            }
        }
    }

    /// A switch. Absence is off. Another arm is a fault.
    pub(super) fn switch(&mut self, name: &str) -> bool {
        match self.take(name).cloned() {
            None => false,
            Some(Value::Switch(on)) => on,
            Some(other) => {
                self.syntax(name, &other.render(), "a switch");
                false
            }
        }
    }
}
