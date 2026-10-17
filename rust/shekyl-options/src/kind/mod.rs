// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Value kinds and their parsers (IG-6).
//!
//! A kind is a syntax. Each kind has one command-line form and one file
//! form; [`Kind::parse_cli`] and [`Kind::parse_file`] turn either into the
//! same [`Value`], so a value means the same thing on both surfaces (IG-12
//! relies on that). A row narrows its kind with a constraint the kind
//! carries; the parser enforces it.
//!
//! Only the kinds the daemon's table uses are here. The wallet binaries add
//! theirs (hash, amount, name, text) with their own tables.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::diagnostic::{Code, Fault};

/// What a quantity measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dimension {
    /// Bytes: `B KiB MiB GiB TiB`.
    Bytes,
    /// Bytes per second: the byte units over `/s`.
    Rate,
    /// A duration: `ms s min h d`.
    Duration,
}

/// A constraint on an endpoint's address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointRule {
    /// Any literal address.
    Any,
    /// Loopback only (RT-14: a plaintext listener never binds beyond it).
    Loopback,
    /// A global unicast address: what a peer on the internet can reach.
    GlobalUnicast,
}

/// A constraint on a peer endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRule {
    /// An IP endpoint or a v3 onion.
    Any,
    /// A v3 onion only.
    OnionOnly,
}

/// The closed key set of a map, checked by reference to its owner (IG-6:
/// "keys are a closed set named in the row").
#[derive(Clone, Copy)]
pub struct KeyRule {
    /// How the keys are described in a refusal.
    pub describe: &'static str,
    /// Whether a key belongs to the set.
    pub check: fn(&str) -> bool,
}

impl fmt::Debug for KeyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRule")
            .field("describe", &self.describe)
            .finish_non_exhaustive()
    }
}

/// A value kind with its row's constraint.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    /// On or off; given alone on the command line; defaults to off.
    Switch,
    /// One word from a closed lowercase set.
    OneOf(&'static [&'static str]),
    /// A decimal integer at least `min`, or one of `keywords`.
    Integer {
        /// The least accepted value.
        min: u64,
        /// Words accepted in place of a number (`auto`).
        keywords: &'static [&'static str],
    },
    /// An integer and a unit, or one of `keywords`.
    Quantity {
        /// What the quantity measures.
        dimension: Dimension,
        /// The least accepted amount, in the dimension's base unit.
        min: u64,
        /// Words accepted in place of a quantity (`unlimited`).
        keywords: &'static [&'static str],
    },
    /// A literal IP address and a port; no hostnames.
    Endpoint(EndpointRule),
    /// An IP endpoint or a v3 onion with a port.
    PeerEndpoint(PeerRule),
    /// A Shekyl address; checked against the network by its owner.
    Address,
    /// An absolute path.
    Path,
    /// A secret: file only, never echoed, zeroized.
    Secret,
    /// A command: file only, an argument array run without a shell, with
    /// `{name}` placeholders from a closed set.
    Command {
        /// The placeholders the command may use.
        placeholders: &'static [&'static str],
    },
    /// An explicit web origin: `http` or `https`, a host, an optional port.
    Origin,
    /// A list of a scalar kind; `none` is the empty list.
    List(&'static Kind),
    /// A map from a closed key set to a scalar kind; `none` is the empty map.
    Map {
        /// The keys the map accepts.
        keys: KeyRule,
        /// The values' kind.
        value: &'static Kind,
    },
}

/// A peer endpoint value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeerEndpoint {
    /// A literal IP endpoint.
    Ip(SocketAddr),
    /// A v3 onion service and its virtual port.
    Onion {
        /// The 56-character service id followed by `.onion`.
        host: String,
        /// The virtual port.
        port: u16,
    },
}

impl fmt::Display for PeerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Onion { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// A secret's text. It is zeroized when dropped, and its `Debug` form never
/// shows it (IG-6, rule 35).
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// The secret's text, for the one owner that hands it on.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(set)")
    }
}

/// A parsed value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// A switch.
    Switch(bool),
    /// A word from a one-of set, or a keyword a row admits.
    Word(&'static str),
    /// An integer.
    Integer(u64),
    /// A byte count.
    Bytes(u64),
    /// Bytes per second.
    Rate(u64),
    /// A duration.
    Duration(Duration),
    /// A literal endpoint.
    Endpoint(SocketAddr),
    /// A peer endpoint.
    Peer(PeerEndpoint),
    /// A Shekyl address, unchecked against the network.
    Address(String),
    /// An absolute path.
    Path(PathBuf),
    /// A secret.
    Secret(Secret),
    /// A command's argument array.
    Command(Vec<String>),
    /// A web origin, in its normal spelling.
    Origin(String),
    /// A list; empty is `none`.
    List(Vec<Value>),
    /// A map; empty is `none`.
    Map(BTreeMap<String, Value>),
}

impl Value {
    /// The text that, given back on either surface, builds this value
    /// (IG-12: what `option show` prints, `option set` accepts). A secret
    /// renders as `set`; its text is never returned here.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Switch(on) => if *on { "true" } else { "false" }.to_owned(),
            Self::Word(w) => (*w).to_owned(),
            Self::Integer(n) => n.to_string(),
            Self::Bytes(n) => render_bytes(*n, ""),
            Self::Rate(n) => render_bytes(*n, "/s"),
            Self::Duration(d) => render_duration(*d),
            Self::Endpoint(addr) => addr.to_string(),
            Self::Peer(peer) => peer.to_string(),
            Self::Address(a) | Self::Origin(a) => a.clone(),
            Self::Path(p) => p.display().to_string(),
            Self::Secret(_) => "set".to_owned(),
            Self::Command(args) => format!("{args:?}"),
            Self::List(items) => {
                if items.is_empty() {
                    "none".to_owned()
                } else {
                    items
                        .iter()
                        .map(Value::render)
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            }
            Self::Map(map) => {
                if map.is_empty() {
                    "none".to_owned()
                } else {
                    map.iter()
                        .map(|(k, v)| format!("{k}={}", v.render()))
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            }
        }
    }
}

const BYTE_UNITS: [(&str, u64); 5] = [
    ("TiB", 1 << 40),
    ("GiB", 1 << 30),
    ("MiB", 1 << 20),
    ("KiB", 1 << 10),
    ("B", 1),
];

const DURATION_UNITS: [(&str, u64); 5] = [
    ("d", 86_400_000),
    ("h", 3_600_000),
    ("min", 60_000),
    ("s", 1_000),
    ("ms", 1),
];

fn render_bytes(n: u64, suffix: &str) -> String {
    for (unit, size) in BYTE_UNITS {
        if n != 0 && n.is_multiple_of(size) {
            return format!("{}{unit}{suffix}", n / size);
        }
    }
    format!("0B{suffix}")
}

fn render_duration(d: Duration) -> String {
    let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    for (unit, size) in DURATION_UNITS {
        if ms != 0 && ms.is_multiple_of(size) {
            return format!("{}{unit}", ms / size);
        }
    }
    "0ms".to_owned()
}

fn syntax(value: &str, expected: &str) -> Fault {
    Fault::new(Code::ValueSyntax)
        .param("value", value)
        .param("expected", expected)
}

fn range(value: &str, rule: impl Into<String>) -> Fault {
    Fault::new(Code::ValueRange)
        .param("value", value)
        .param("rule", rule)
}

fn words(list: &[&str]) -> String {
    list.iter()
        .map(|w| format!("`{w}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A plain unsigned decimal: digits only, no sign, no separators.
fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn keyword(text: &str, keywords: &'static [&'static str]) -> Option<&'static str> {
    keywords.iter().copied().find(|k| *k == text)
}

impl Kind {
    /// Whether the kind may be given on the command line at all.
    #[must_use]
    pub const fn cli_allowed(&self) -> bool {
        !matches!(self, Self::Secret | Self::Command { .. })
    }

    /// Whether the kind takes no value on the command line.
    #[must_use]
    pub const fn is_switch(&self) -> bool {
        matches!(self, Self::Switch)
    }

    /// Whether the kind collects repeated command-line values.
    #[must_use]
    pub const fn is_collection(&self) -> bool {
        matches!(self, Self::List(_) | Self::Map { .. })
    }

    /// Parses the command line's values for this kind: none for a switch,
    /// one for a scalar, one per repetition for a list or a map.
    ///
    /// # Errors
    /// A [`Fault`] naming what is wrong with the first value that fails.
    pub fn parse_cli(&self, values: &[String]) -> Result<Value, Fault> {
        match self {
            Self::Switch => Ok(Value::Switch(true)),
            Self::List(item) => {
                if values.len() == 1 && values[0] == "none" {
                    return Ok(Value::List(Vec::new()));
                }
                let mut out = Vec::with_capacity(values.len());
                for v in values {
                    if v == "none" {
                        return Err(range("none", "`none` stands alone; it is the empty list"));
                    }
                    out.push(item.parse_text(v)?);
                }
                Ok(Value::List(out))
            }
            Self::Map { keys, value } => {
                if values.len() == 1 && values[0] == "none" {
                    return Ok(Value::Map(BTreeMap::new()));
                }
                let mut out = BTreeMap::new();
                for v in values {
                    let Some((k, val)) = v.split_once('=') else {
                        return Err(syntax(v, "`key=value`"));
                    };
                    insert_key(&mut out, keys, k, value.parse_text(val)?)?;
                }
                Ok(Value::Map(out))
            }
            _ => match values {
                [one] => self.parse_text(one),
                _ => Err(Fault::new(Code::CliRepeated)),
            },
        }
    }

    /// Parses the file's TOML value for this kind.
    ///
    /// # Errors
    /// A [`Fault`] naming what is wrong.
    pub fn parse_file(&self, value: &toml::Value) -> Result<Value, Fault> {
        match (self, value) {
            (Self::Switch, toml::Value::Boolean(b)) => Ok(Value::Switch(*b)),
            (Self::Switch, other) => Err(syntax(&shown(other), "`true` or `false`")),
            // A keyword such as `auto` arrives as a string and takes the
            // string arm below.
            (Self::Integer { min, .. }, toml::Value::Integer(n)) => {
                let shown_n = n.to_string();
                let n =
                    u64::try_from(*n).map_err(|_| range(&shown_n, format!("at least {min}")))?;
                check_min(n, *min, &shown_n)?;
                Ok(Value::Integer(n))
            }
            (Self::Secret, toml::Value::String(s)) => {
                if s.is_empty() {
                    return Err(syntax("", "a non-empty secret"));
                }
                Ok(Value::Secret(Secret(Zeroizing::new(s.clone()))))
            }
            (Self::Secret, _) => Err(syntax("(not shown)", "a string")),
            (Self::Command { placeholders }, toml::Value::Array(items)) => {
                parse_command(items, placeholders)
            }
            (Self::Command { .. }, other) => Err(syntax(
                &shown(other),
                "an array of strings, the program first: [\"/path/prog\", \"arg\"]",
            )),
            (Self::List(_), toml::Value::String(s)) if s == "none" => Ok(Value::List(Vec::new())),
            (Self::List(item), toml::Value::Array(items)) => {
                if items.is_empty() {
                    return Err(syntax(
                        "[]",
                        "a non-empty list; write `\"none\"` for the empty list",
                    ));
                }
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    out.push(item.parse_file(it)?);
                }
                Ok(Value::List(out))
            }
            (Self::List(_), other) => Err(syntax(&shown(other), "an array, or `\"none\"`")),
            (Self::Map { .. }, toml::Value::String(s)) if s == "none" => {
                Ok(Value::Map(BTreeMap::new()))
            }
            (Self::Map { keys, value }, toml::Value::Table(t)) => {
                if t.is_empty() {
                    return Err(syntax(
                        "{}",
                        "a non-empty table; write `\"none\"` for the empty map",
                    ));
                }
                let mut out = BTreeMap::new();
                for (k, v) in t {
                    insert_key(&mut out, keys, k, value.parse_file(v)?)?;
                }
                Ok(Value::Map(out))
            }
            (Self::Map { .. }, other) => Err(syntax(&shown(other), "a table, or `\"none\"`")),
            (_, toml::Value::String(s)) => self.parse_text(s),
            (_, other) => Err(syntax(&shown(other), self.expected())),
        }
    }

    /// Parses one scalar's text: a command-line value, a list element, a
    /// map value, or a file string.
    ///
    /// # Errors
    /// A [`Fault`] naming what is wrong.
    pub fn parse_text(&self, text: &str) -> Result<Value, Fault> {
        match self {
            Self::Switch => Err(syntax(text, "a switch, which takes no value")),
            Self::OneOf(set) => keyword(text, set).map(Value::Word).ok_or_else(|| {
                Fault::new(Code::ValueWord)
                    .param("value", text)
                    .param("words", words(set))
            }),
            Self::Integer { min, keywords } => {
                if let Some(k) = keyword(text, keywords) {
                    return Ok(Value::Word(k));
                }
                let n = decimal(text).ok_or_else(|| syntax(text, self.expected()))?;
                check_min(n, *min, text)?;
                Ok(Value::Integer(n))
            }
            Self::Quantity {
                dimension,
                min,
                keywords,
            } => {
                if let Some(k) = keyword(text, keywords) {
                    return Ok(Value::Word(k));
                }
                parse_quantity(text, *dimension, *min)
            }
            Self::Endpoint(rule) => parse_endpoint(text, *rule).map(Value::Endpoint),
            Self::PeerEndpoint(rule) => parse_peer(text, *rule).map(Value::Peer),
            Self::Address => {
                if text.is_empty() || text.chars().any(char::is_whitespace) {
                    return Err(syntax(text, "a Shekyl address"));
                }
                Ok(Value::Address(text.to_owned()))
            }
            Self::Path => {
                let p = PathBuf::from(text);
                if !p.is_absolute() {
                    return Err(syntax(text, "an absolute path"));
                }
                Ok(Value::Path(p))
            }
            Self::Origin => parse_origin(text).map(Value::Origin),
            Self::Secret | Self::Command { .. } => Err(Fault::new(Code::ValueSurface)
                .param("given", "the command line")
                .param("allowed", "in the configuration file")),
            Self::List(_) | Self::Map { .. } => Err(syntax(text, self.expected())),
        }
    }

    /// How the kind's syntax is described in a refusal.
    #[must_use]
    pub fn expected(&self) -> &'static str {
        match self {
            Self::Switch => "a switch",
            Self::OneOf(_) => "one of the row's words",
            Self::Integer { .. } => "a decimal integer",
            Self::Quantity {
                dimension: Dimension::Bytes,
                ..
            } => "a byte quantity such as `512MiB`",
            Self::Quantity {
                dimension: Dimension::Rate,
                ..
            } => "a rate such as `1MiB/s`",
            Self::Quantity {
                dimension: Dimension::Duration,
                ..
            } => "a duration such as `30s`",
            Self::Endpoint(_) => {
                "a literal IP address and port, such as `127.0.0.1:11029` or `[::1]:11029`"
            }
            Self::PeerEndpoint(PeerRule::Any) => "an IP endpoint or a v3 onion with a port",
            Self::PeerEndpoint(PeerRule::OnionOnly) => "a v3 onion with a port",
            Self::Address => "a Shekyl address",
            Self::Path => "an absolute path",
            Self::Secret => "a secret",
            Self::Command { .. } => "an array of strings",
            Self::Origin => "a web origin such as `https://example.org`",
            Self::List(_) => "a list",
            Self::Map { .. } => "a map",
        }
    }
}

/// A file value as a refusal quotes it.
fn shown(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Float(_) => "a floating-point number".to_owned(),
        toml::Value::Datetime(d) => d.to_string(),
        toml::Value::Array(_) => "an array".to_owned(),
        toml::Value::Table(_) => "a table".to_owned(),
    }
}

fn check_min(n: u64, min: u64, text: &str) -> Result<(), Fault> {
    if n < min {
        return Err(range(text, format!("at least {min}")));
    }
    Ok(())
}

fn insert_key(
    out: &mut BTreeMap<String, Value>,
    keys: &KeyRule,
    key: &str,
    value: Value,
) -> Result<(), Fault> {
    if !(keys.check)(key) {
        return Err(Fault::new(Code::ValueWord)
            .param("value", key)
            .param("words", keys.describe));
    }
    if out.insert(key.to_owned(), value).is_some() {
        return Err(range(key, "each key once"));
    }
    Ok(())
}

fn parse_quantity(text: &str, dimension: Dimension, min: u64) -> Result<Value, Fault> {
    let digits_end = text
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(digits_end);
    let unit_shown = match dimension {
        Dimension::Bytes => "`B`, `KiB`, `MiB`, `GiB`, `TiB`",
        Dimension::Rate => "`B/s`, `KiB/s`, `MiB/s`, `GiB/s`, `TiB/s`",
        Dimension::Duration => "`ms`, `s`, `min`, `h`, `d`",
    };
    let Some(n) = decimal(number) else {
        return Err(syntax(text, "an integer followed by a unit"));
    };
    let unit_fault = || {
        Fault::new(Code::ValueUnit)
            .param("value", text)
            .param("units", unit_shown)
    };
    let size = match dimension {
        Dimension::Bytes => BYTE_UNITS.iter().find(|(u, _)| *u == unit).map(|(_, s)| *s),
        Dimension::Rate => unit
            .strip_suffix("/s")
            .and_then(|u| BYTE_UNITS.iter().find(|(name, _)| *name == u))
            .map(|(_, s)| *s),
        Dimension::Duration => DURATION_UNITS
            .iter()
            .find(|(u, _)| *u == unit)
            .map(|(_, s)| *s),
    }
    .ok_or_else(unit_fault)?;
    let total = n
        .checked_mul(size)
        .ok_or_else(|| range(text, "too large to represent"))?;
    check_min(total, min, text)?;
    Ok(match dimension {
        Dimension::Bytes => Value::Bytes(total),
        Dimension::Rate => Value::Rate(total),
        Dimension::Duration => Value::Duration(Duration::from_millis(total)),
    })
}

fn parse_endpoint(text: &str, rule: EndpointRule) -> Result<SocketAddr, Fault> {
    let addr: SocketAddr = text.parse().map_err(|_| {
        syntax(
            text,
            "a literal IP address and port, such as `127.0.0.1:11029` or `[::1]:11029`",
        )
    })?;
    if addr.port() == 0 {
        return Err(range(text, "a port from 1 to 65535"));
    }
    match rule {
        EndpointRule::Any => {}
        EndpointRule::Loopback => {
            if !addr.ip().is_loopback() {
                return Err(range(
                    text,
                    "a loopback address: a plaintext listener never binds beyond loopback (RT-14)",
                ));
            }
        }
        EndpointRule::GlobalUnicast => {
            if !is_global_unicast(addr.ip()) {
                return Err(range(
                    text,
                    "a global unicast address, one a peer on the internet can reach",
                ));
            }
        }
    }
    Ok(addr)
}

/// Whether a peer on the internet can reach the address: not loopback,
/// private, link-local, shared, documentation, benchmarking, multicast,
/// broadcast or unspecified.
#[must_use]
pub fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let shared = a == 100 && (b & 0xc0) == 64; // 100.64.0.0/10
    let benchmarking = a == 198 && (b & 0xfe) == 18; // 198.18.0.0/15
    let reserved = a >= 240; // 240.0.0.0/4 and broadcast
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || shared
        || benchmarking
        || reserved)
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let global_unicast = (s[0] & 0xe000) == 0x2000; // 2000::/3
    let documentation = s[0] == 0x2001 && s[1] == 0x0db8; // 2001:db8::/32
    global_unicast && !documentation
}

fn parse_peer(text: &str, rule: PeerRule) -> Result<PeerEndpoint, Fault> {
    if let Some((host, port)) = text.rsplit_once(':') {
        if host.ends_with(".onion") {
            let port: u16 = decimal(port)
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p != 0)
                .ok_or_else(|| range(text, "a port from 1 to 65535"))?;
            if shekyl_onion_v3::v3_pubkey(host).is_none() {
                return Err(syntax(
                    text,
                    "a v3 onion address (56 base32 characters and `.onion`) with a valid checksum",
                ));
            }
            return Ok(PeerEndpoint::Onion {
                host: host.to_owned(),
                port,
            });
        }
    }
    if rule == PeerRule::OnionOnly {
        return Err(syntax(text, "a v3 onion with a port"));
    }
    parse_endpoint(text, EndpointRule::Any).map(PeerEndpoint::Ip)
}

fn parse_origin(text: &str) -> Result<String, Fault> {
    if text == "*" {
        return Err(range(
            text,
            "an explicit origin; `*` would let any page in the operator's browser read and drive the listener",
        ));
    }
    let expected =
        "a web origin: `http://` or `https://`, a host, an optional port, and nothing after";
    let (scheme, rest) = text
        .split_once("://")
        .ok_or_else(|| syntax(text, expected))?;
    if scheme != "http" && scheme != "https" {
        return Err(syntax(text, expected));
    }
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return Err(syntax(text, expected));
    }
    let host = if let Some(stripped) = rest.strip_prefix('[') {
        let (inside, after) = stripped
            .split_once(']')
            .ok_or_else(|| syntax(text, expected))?;
        inside
            .parse::<Ipv6Addr>()
            .map_err(|_| syntax(text, expected))?;
        if !after.is_empty() {
            origin_port(
                after
                    .strip_prefix(':')
                    .ok_or_else(|| syntax(text, expected))?,
                text,
            )?;
        }
        inside
    } else {
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        if let Some(p) = port {
            origin_port(p, text)?;
        }
        host
    };
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if host.is_empty() || !(host.parse::<IpAddr>().is_ok() || host.split('.').all(label_ok)) {
        return Err(syntax(text, expected));
    }
    Ok(text.to_ascii_lowercase())
}

fn origin_port(port: &str, text: &str) -> Result<(), Fault> {
    decimal(port)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
        .map(|_| ())
        .ok_or_else(|| range(text, "a port from 1 to 65535"))
}

fn parse_command(
    items: &[toml::Value],
    placeholders: &'static [&'static str],
) -> Result<Value, Fault> {
    let shape = "an array of strings, the program first: [\"/path/prog\", \"arg\", \"{height}\"]";
    if items.is_empty() {
        return Err(syntax("[]", shape));
    }
    let mut args = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let toml::Value::String(s) = item else {
            return Err(syntax(&shown(item), shape));
        };
        if i == 0 && !PathBuf::from(s).is_absolute() {
            return Err(syntax(
                s,
                "an absolute path to the program, first in the array",
            ));
        }
        check_placeholders(s, placeholders)?;
        args.push(s.clone());
    }
    Ok(Value::Command(args))
}

/// Braces are the only syntax in a command argument: `{name}` is a
/// placeholder from the row's set, and an unmatched brace is refused.
fn check_placeholders(arg: &str, placeholders: &'static [&'static str]) -> Result<(), Fault> {
    let offered = || {
        if placeholders.is_empty() {
            "none".to_owned()
        } else {
            placeholders
                .iter()
                .map(|p| format!("`{{{p}}}`"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let mut rest = arg;
    while let Some(open) = rest.find(['{', '}']) {
        if rest.as_bytes()[open] == b'}' {
            return Err(syntax(
                arg,
                "an argument whose braces enclose a placeholder",
            ));
        }
        let after = &rest[open + 1..];
        let close = after
            .find('}')
            .ok_or_else(|| syntax(arg, "an argument whose braces enclose a placeholder"))?;
        let name = &after[..close];
        if !placeholders.contains(&name) {
            return Err(Fault::new(Code::ValuePlaceholder)
                .param("placeholder", name)
                .param("offered", offered()));
        }
        rest = &after[close + 1..];
    }
    Ok(())
}

#[cfg(test)]
mod tests;
