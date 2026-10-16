// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The asynchronous events the supervisor reads, parsed (`TOR_SUPERVISOR.md` §4.2).
//!
//! The supervisor sends one `SETEVENTS` ([`Command::supervisor_events`]) and reads
//! five event types: `STATUS_GENERAL`, `STATUS_CLIENT`, `NETWORK_LIVENESS`, `HS_DESC`,
//! and the log events `NOTICE`, `WARN` and `ERR`. [`parse_event`] turns one framed
//! `650` reply into a [`TorEvent`].
//!
//! Sans-IO and pure, like [`stream`](super::stream): the known-answer tests below are
//! lines the pinned tor wrote, captured on 2026-10-16 from `tor 0.4.9.13
//! (git-3c575400909efe65)`, the 15.0.24 bundle. Events that cannot be provoked on
//! demand (a clock jump, a skew report, a dangerous version, every directory
//! unreachable, the open-file limit, liveness going down) are built from the format
//! strings in tor's source at tag `tor-0.4.9.13`, and each such test names the file.
//!
//! **Tolerant, as the control specification requires.** An action or keyword this
//! module does not know is not an error: an unknown action is that type's `Other`, an
//! unknown keyword is skipped, and keywords are read by name, never by position. A
//! field that is missing or malformed is `None`.
//!
//! **No keyword is read from inside a quoted value.** `SUMMARY="… PROGRESS=99 …"` and
//! `WARNING="… REASON=…"` carry free text, which tor fills from relay names and error
//! strings. The tokenizer splits on spaces outside quotes and recognises `KEY=` only at
//! the start of a token, so a keyword planted inside a quoted value is part of that
//! value. This is the rule [`bootstrap`](super::bootstrap) states for its own poll.

use super::actor::Command;
use super::framing::{ControlReply, ASYNC_EVENT_STATUS};
use super::onion::ServiceId;
use super::vanguards::RelayFingerprint;

/// The event types the supervisor subscribes to, in the order its one `SETEVENTS`
/// names them (§4.2). Nothing else sends `SETEVENTS` on that connection, because
/// `SETEVENTS` replaces the whole subscription.
pub const SUPERVISOR_EVENTS: [&str; 7] = [
    "STATUS_GENERAL",
    "STATUS_CLIENT",
    "HS_DESC",
    "NETWORK_LIVENESS",
    "NOTICE",
    "WARN",
    "ERR",
];

impl Command {
    /// The supervisor's one `SETEVENTS`: [`SUPERVISOR_EVENTS`].
    ///
    /// Nothing in production sends it yet. The wallet's managed tor stays
    /// unsubscribed (`EventSink::unsubscribed`): SP-T0 §3b withdrew its subscription,
    /// and that retraction stands for the wallet.
    #[must_use]
    pub fn supervisor_events() -> Self {
        Self::SetEvents(SUPERVISOR_EVENTS.iter().map(|e| (*e).to_owned()).collect())
    }
}

/// One asynchronous event, typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorEvent {
    /// `STATUS_GENERAL`.
    General {
        /// The status event's severity.
        severity: Severity,
        /// What it reports.
        status: GeneralStatus,
    },
    /// `STATUS_CLIENT`.
    Client {
        /// The status event's severity.
        severity: Severity,
        /// What it reports.
        status: ClientStatus,
    },
    /// `NETWORK_LIVENESS`.
    NetworkLiveness(Liveness),
    /// `HS_DESC`.
    HsDesc(HsDescEvent),
    /// A log event: `NOTICE`, `WARN` or `ERR`.
    Log(LogEvent),
    /// An event type outside [`SUPERVISOR_EVENTS`]. It carries nothing: the supervisor
    /// did not subscribe to it, so it has no reading here.
    Unsubscribed,
}

/// The severity a status event carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// `NOTICE`.
    Notice,
    /// `WARN`.
    Warn,
    /// `ERR`.
    Err,
    /// Any other word, including tor's `INFO` for a bootstrap problem it does not
    /// yet recommend warning about.
    Other,
}

/// What a `STATUS_GENERAL` event reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralStatus {
    /// `CLOCK_JUMPED TIME=`: tor's clock moved by this many seconds (negative is
    /// backwards) and tor has closed its circuits. The resume input.
    ClockJumped {
        /// `TIME=`, in seconds.
        seconds: Option<i64>,
    },
    /// `CLOCK_SKEW`: a source reported a time that differs from ours. The source is
    /// not authenticated, so this is what tor reports, never that our clock is wrong.
    ClockSkew {
        /// `SKEW=` or `MIN_SKEW=`.
        skew: Option<ClockSkew>,
        /// `SOURCE=`, as tor wrote it (for example `DIRSERV:<address>:<port>`).
        source: Option<String>,
    },
    /// `DANGEROUS_VERSION`: the consensus does not recommend this tor.
    DangerousVersion {
        /// `REASON=`.
        reason: VersionReason,
    },
    /// `DIR_ALL_UNREACHABLE`: every directory tor knows is unreachable.
    DirAllUnreachable,
    /// `TOO_MANY_CONNECTIONS`: tor hit the open-file limit.
    TooManyConnections {
        /// `CURRENT=`, the number of open sockets.
        current: Option<u64>,
    },
    /// An action this module does not read.
    Other,
}

/// A `CLOCK_SKEW` value, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockSkew {
    /// `SKEW=`: the measured difference.
    Measured(i64),
    /// `MIN_SKEW=`: at least this difference.
    AtLeast(i64),
}

/// A `DANGEROUS_VERSION` `REASON=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionReason {
    /// `NEW`: newer than any recommended version.
    New,
    /// `OBSOLETE`: older than every recommended version in its series.
    Obsolete,
    /// `UNRECOMMENDED`: not recommended.
    Unrecommended,
    /// Missing, or a word this module does not know.
    Other,
}

/// What a `STATUS_CLIENT` event reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientStatus {
    /// `BOOTSTRAP`: progress, and the problem form when one is reported.
    Bootstrap(Bootstrap),
    /// `ENOUGH_DIR_INFO`.
    EnoughDirInfo,
    /// `NOT_ENOUGH_DIR_INFO`.
    NotEnoughDirInfo,
    /// `CIRCUIT_ESTABLISHED`.
    CircuitEstablished,
    /// `CIRCUIT_NOT_ESTABLISHED REASON=`.
    CircuitNotEstablished {
        /// `REASON=` (`EXTERNAL_ADDRESS`, `DIR_ALL_UNREACHABLE`, `CLOCK_JUMPED`).
        reason: Option<String>,
    },
    /// An action this module does not read (`CONSENSUS_ARRIVED`, among others).
    Other,
}

/// A `BOOTSTRAP` status event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    /// `PROGRESS=`, a percentage.
    pub progress: Option<u8>,
    /// `TAG=`, the phase's name.
    pub tag: Option<String>,
    /// The problem form, present when the event carries `WARNING=` or `REASON=`.
    pub problem: Option<BootstrapProblem>,
}

/// The problem form of a `BOOTSTRAP` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapProblem {
    /// `WARNING=`, tor's text for the failure.
    pub warning: Option<String>,
    /// `REASON=` (`CONNECTREFUSED`, `TIMEOUT`, `NOROUTE`, …).
    pub reason: Option<String>,
    /// `COUNT=`, how many such problems tor has seen at this phase.
    pub count: Option<u32>,
    /// `RECOMMENDATION=`. Tor sends `warn` from the tenth problem at a phase.
    pub recommendation: Recommendation,
}

/// A bootstrap problem's `RECOMMENDATION=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    /// `ignore`.
    Ignore,
    /// `warn`: §4.2's named external cause.
    Warn,
    /// Missing, or a word this module does not know.
    Other,
}

/// A `NETWORK_LIVENESS` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// `UP`.
    Up,
    /// `DOWN`.
    Down,
    /// A word this module does not know.
    Other,
}

/// An `HS_DESC` event. Tor sends these for descriptors we upload and for descriptors
/// it fetches for onions we dial, so a reader filters by [`Self::address`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsDescEvent {
    /// The action.
    pub action: HsDescAction,
    /// The onion address, without `.onion`. `None` when tor wrote `UNKNOWN`.
    pub address: Option<ServiceId>,
    /// The HSDir, from tor's `$<fingerprint>~<nickname>`. `None` when tor wrote
    /// `UNKNOWN` (a `CREATED` event names none).
    pub hsdir: Option<RelayFingerprint>,
    /// The descriptor id, when the action carries one. An upload's end (`UPLOADED`,
    /// and `FAILED` for an upload) carries none; a fetch's `FAILED` does, which is how
    /// the two `FAILED`s are told apart.
    pub descriptor_id: Option<String>,
    /// `REASON=`, on a `FAILED`.
    pub reason: Option<String>,
}

/// An `HS_DESC` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsDescAction {
    /// `REQUESTED`: a fetch began.
    Requested,
    /// `UPLOAD`: an upload to one HSDir began.
    Upload,
    /// `RECEIVED`: a fetch completed.
    Received,
    /// `UPLOADED`: an upload to one HSDir completed.
    Uploaded,
    /// `IGNORE`.
    Ignore,
    /// `FAILED`: a fetch or an upload failed.
    Failed,
    /// `CREATED`: tor built a descriptor.
    Created,
    /// An action this module does not know.
    Other,
}

/// A log event, for the daemon's `tor` log category (§4.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    /// The log severity.
    pub severity: LogSeverity,
    /// The message, as tor sent it. Tor replaces any newline in a log message before
    /// it sends the event, so this is one line.
    pub message: String,
}

/// A log event's severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSeverity {
    /// `NOTICE`.
    Notice,
    /// `WARN`.
    Warn,
    /// `ERR`.
    Err,
}

/// Parse one framed reply into a [`TorEvent`]. `None` if it is not a `650` event.
#[must_use]
pub fn parse_event(reply: &ControlReply) -> Option<TorEvent> {
    if reply.status() != ASYNC_EVENT_STATUS {
        return None;
    }
    let line = reply.lines().first()?;
    Some(parse_event_line(line))
}

/// Parse an event line: the `650` reply's first line, with the status stripped.
fn parse_event_line(line: &str) -> TorEvent {
    let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
    match kind {
        "STATUS_GENERAL" => {
            let (severity, fields) = status_fields(rest);
            TorEvent::General {
                severity,
                status: general_status(&fields),
            }
        }
        "STATUS_CLIENT" => {
            let (severity, fields) = status_fields(rest);
            TorEvent::Client {
                severity,
                status: client_status(&fields),
            }
        }
        "NETWORK_LIVENESS" => TorEvent::NetworkLiveness(match rest.trim() {
            "UP" => Liveness::Up,
            "DOWN" => Liveness::Down,
            _ => Liveness::Other,
        }),
        "HS_DESC" => TorEvent::HsDesc(hs_desc(&Fields::of(rest))),
        "NOTICE" => log(LogSeverity::Notice, rest),
        "WARN" => log(LogSeverity::Warn, rest),
        "ERR" => log(LogSeverity::Err, rest),
        _ => TorEvent::Unsubscribed,
    }
}

fn log(severity: LogSeverity, message: &str) -> TorEvent {
    TorEvent::Log(LogEvent {
        severity,
        message: message.to_owned(),
    })
}

/// A status event is `<SEVERITY> <ACTION> <ARGS>`.
fn status_fields(rest: &str) -> (Severity, Fields) {
    let fields = Fields::of(rest);
    let severity = match fields.positional(0) {
        Some("NOTICE") => Severity::Notice,
        Some("WARN") => Severity::Warn,
        Some("ERR") => Severity::Err,
        _ => Severity::Other,
    };
    (severity, fields)
}

/// The highest `PROGRESS=`: it is a percentage.
const MAX_PROGRESS: u8 = 100;

/// The action is the status event's second positional field.
const STATUS_ACTION: usize = 1;

fn general_status(fields: &Fields) -> GeneralStatus {
    match fields.positional(STATUS_ACTION) {
        Some("CLOCK_JUMPED") => GeneralStatus::ClockJumped {
            seconds: fields.number("TIME"),
        },
        Some("CLOCK_SKEW") => GeneralStatus::ClockSkew {
            skew: fields
                .number("SKEW")
                .map(ClockSkew::Measured)
                .or_else(|| fields.number("MIN_SKEW").map(ClockSkew::AtLeast)),
            source: fields.text("SOURCE"),
        },
        Some("DANGEROUS_VERSION") => GeneralStatus::DangerousVersion {
            reason: match fields.value("REASON") {
                Some("NEW") => VersionReason::New,
                Some("OBSOLETE") => VersionReason::Obsolete,
                Some("UNRECOMMENDED") => VersionReason::Unrecommended,
                _ => VersionReason::Other,
            },
        },
        Some("DIR_ALL_UNREACHABLE") => GeneralStatus::DirAllUnreachable,
        Some("TOO_MANY_CONNECTIONS") => GeneralStatus::TooManyConnections {
            current: fields.number("CURRENT"),
        },
        _ => GeneralStatus::Other,
    }
}

fn client_status(fields: &Fields) -> ClientStatus {
    match fields.positional(STATUS_ACTION) {
        Some("BOOTSTRAP") => ClientStatus::Bootstrap(bootstrap(fields)),
        Some("ENOUGH_DIR_INFO") => ClientStatus::EnoughDirInfo,
        Some("NOT_ENOUGH_DIR_INFO") => ClientStatus::NotEnoughDirInfo,
        Some("CIRCUIT_ESTABLISHED") => ClientStatus::CircuitEstablished,
        Some("CIRCUIT_NOT_ESTABLISHED") => ClientStatus::CircuitNotEstablished {
            reason: fields.text("REASON"),
        },
        _ => ClientStatus::Other,
    }
}

fn bootstrap(fields: &Fields) -> Bootstrap {
    let problem = (fields.has("WARNING") || fields.has("REASON")).then(|| BootstrapProblem {
        warning: fields.text("WARNING"),
        reason: fields.text("REASON"),
        count: fields.number("COUNT"),
        recommendation: match fields.value("RECOMMENDATION") {
            Some("ignore") => Recommendation::Ignore,
            Some("warn") => Recommendation::Warn,
            _ => Recommendation::Other,
        },
    });
    Bootstrap {
        // A percentage: a number above 100 is malformed, as `bootstrap` reads it.
        progress: fields
            .number("PROGRESS")
            .filter(|progress| *progress <= MAX_PROGRESS),
        tag: fields.text("TAG"),
        problem,
    }
}

/// `HS_DESC <ACTION> <ADDRESS> <AUTH> <HSDIR> [<DESCRIPTOR_ID>] [KEY=VALUE …]`.
fn hs_desc(fields: &Fields) -> HsDescEvent {
    /// Positional fields, in tor's order.
    const ACTION: usize = 0;
    const ADDRESS: usize = 1;
    const HSDIR: usize = 3;
    const DESCRIPTOR_ID: usize = 4;
    let action = match fields.positional(ACTION) {
        Some("REQUESTED") => HsDescAction::Requested,
        Some("UPLOAD") => HsDescAction::Upload,
        Some("RECEIVED") => HsDescAction::Received,
        Some("UPLOADED") => HsDescAction::Uploaded,
        Some("IGNORE") => HsDescAction::Ignore,
        Some("FAILED") => HsDescAction::Failed,
        Some("CREATED") => HsDescAction::Created,
        _ => HsDescAction::Other,
    };
    HsDescEvent {
        action,
        address: fields.positional(ADDRESS).and_then(ServiceId::parse),
        hsdir: fields.positional(HSDIR).and_then(hsdir_fingerprint),
        descriptor_id: fields.positional(DESCRIPTOR_ID).map(str::to_owned),
        reason: fields.text("REASON"),
    }
}

/// Tor names an HSDir as `$<40 hex>~<nickname>` (or `=` in older tors). The
/// fingerprint is the part before the separator.
fn hsdir_fingerprint(longname: &str) -> Option<RelayFingerprint> {
    let fingerprint = longname.split(['~', '=']).next().unwrap_or(longname);
    fingerprint
        .starts_with('$')
        .then(|| RelayFingerprint::parse(fingerprint))
        .flatten()
}

// --- Tokens ------------------------------------------------------------------

/// One space-separated token of an event line.
#[derive(Debug, PartialEq, Eq)]
struct Token {
    /// `KEY` of a `KEY=VALUE` token, recognised only at the token's start and outside
    /// quotes. `None` for a positional token.
    key: Option<String>,
    /// The value, with a quoted string unquoted and its escapes decoded.
    value: String,
}

/// An event line's tokens, read by position or by keyword.
struct Fields(Vec<Token>);

impl Fields {
    fn of(line: &str) -> Self {
        Self(tokens(line))
    }

    /// The `index`th positional token, counting only tokens with no key.
    fn positional(&self, index: usize) -> Option<&str> {
        self.0
            .iter()
            .filter(|t| t.key.is_none())
            .nth(index)
            .map(|t| t.value.as_str())
    }

    /// The value of the first `key=` token.
    fn value(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|t| t.key.as_deref() == Some(key))
            .map(|t| t.value.as_str())
    }

    fn has(&self, key: &str) -> bool {
        self.value(key).is_some()
    }

    fn text(&self, key: &str) -> Option<String> {
        self.value(key).map(str::to_owned)
    }

    fn number<T: std::str::FromStr>(&self, key: &str) -> Option<T> {
        self.value(key)?.parse().ok()
    }
}

/// Split an event line into tokens: on spaces outside double quotes. A token whose
/// leading characters are a keyword and `=` is a keyword token; the keyword test runs
/// before any quote is opened, so nothing inside a quoted value becomes a keyword.
fn tokens(line: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if_eq(&' ').is_some() {}
        if chars.peek().is_none() {
            return tokens;
        }
        let mut raw = String::new();
        let mut quoted = false;
        while let Some(c) = chars.next() {
            match c {
                ' ' if !quoted => break,
                '"' => {
                    quoted = !quoted;
                    raw.push(c);
                }
                '\\' if quoted => {
                    raw.push(c);
                    if let Some(escaped) = chars.next() {
                        raw.push(escaped);
                    }
                }
                _ => raw.push(c),
            }
        }
        tokens.push(token(&raw));
    }
}

fn token(raw: &str) -> Token {
    let key_end = raw
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|&end| end > 0 && raw[end..].starts_with('='));
    match key_end {
        Some(end) => Token {
            key: Some(raw[..end].to_owned()),
            value: unquote(&raw[end + 1..]),
        },
        None => Token {
            key: None,
            value: unquote(raw),
        },
    }
}

/// Decode a control-spec `QuotedString`; a value with no surrounding quotes is
/// returned as it is. `\\`, `\"`, `\n`, `\r` and `\t` are decoded; any other escaped
/// character stands for itself.
fn unquote(raw: &str) -> String {
    let Some(inner) = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) else {
        return raw.to_owned();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

// --- Upload rounds -----------------------------------------------------------

/// The descriptor upload rounds of one onion address, coalesced from its `HS_DESC`
/// events (`TSR-Q5`).
///
/// Tor uploads each of a service's descriptors to several HSDirs: `UPLOAD` when an
/// upload to one HSDir begins, then `UPLOADED` or `FAILED` when it ends. The pinned
/// tor's first round for a new service was sixteen uploads, two descriptors to eight
/// HSDirs each. A round opens at the first `UPLOAD` while none is open, and ends when
/// every upload it opened has ended. The two descriptors can share an HSDir, so the
/// open uploads are a multiset, not a set.
///
/// [`RoundMark::FirstUploaded`] is the probe's one trigger per round. A round in which
/// no upload succeeded ends with `uploaded == 0`, which is §4.4's Service-class
/// evidence.
///
/// **A round whose ends do not all arrive still ends.** Tor starts every upload of a
/// round in one pass of its main loop, before any HSDir can have answered (tor
/// 0.4.9.13, `run_upload_descriptor_event` → `upload_descriptor_to_all`), so an
/// `UPLOAD` that arrives once the open round's uploads have begun to end belongs to the
/// next round: the open one ends there, counting the uploads that never reported in
/// `unfinished`, and the next one starts and can trigger again. An end that is lost
/// (the bounded event sink drops events when its consumer falls behind) leaves the
/// round open until then; a consumer that sees the sink drop events calls
/// [`Self::resync`] to end it at once.
///
/// Only an upload's own end closes it. A `FAILED` that carries a descriptor id is a
/// fetch's (the self-probe fetches our own descriptor), and closes nothing. An
/// `UPLOADED` or `FAILED` naming an HSDir with no open upload, as when the subscription
/// began mid-round, is ignored.
pub struct UploadRounds {
    address: ServiceId,
    open: Vec<RelayFingerprint>,
    uploaded: u32,
    failed: u32,
    triggered: bool,
}

/// A boundary in a round of uploads, reported by [`UploadRounds::observe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundMark {
    /// The first upload of a round began.
    Started,
    /// The first upload of this round succeeded: the probe's trigger.
    FirstUploaded,
    /// The round ended: every upload it began has ended, the next round began, or the
    /// consumer resynchronised.
    Ended {
        /// Uploads that succeeded.
        uploaded: u32,
        /// Uploads that failed.
        failed: u32,
        /// Uploads that began and reported no end.
        unfinished: u32,
    },
}

impl UploadRounds {
    /// Track the rounds of `address`'s descriptors.
    #[must_use]
    pub fn new(address: ServiceId) -> Self {
        Self {
            address,
            open: Vec::new(),
            uploaded: 0,
            failed: 0,
            triggered: false,
        }
    }

    /// Whether a round is open.
    #[must_use]
    pub fn in_round(&self) -> bool {
        !self.open.is_empty()
    }

    /// Fold one event in. Returns the boundaries it crossed, in order: an `UPLOADED`
    /// that is both the round's first success and its last end returns
    /// [`RoundMark::FirstUploaded`] then [`RoundMark::Ended`].
    pub fn observe(&mut self, event: &HsDescEvent) -> Vec<RoundMark> {
        if event.address.as_ref() != Some(&self.address) {
            return Vec::new();
        }
        let Some(hsdir) = event.hsdir else {
            return Vec::new();
        };
        match event.action {
            HsDescAction::Upload => {
                let mut marks = Vec::new();
                // The open round's uploads have begun to end, so this one is the next
                // round's: tor starts a round's uploads before any of them ends.
                if self.in_round() && self.uploaded + self.failed > 0 {
                    marks.push(self.end());
                }
                if !self.in_round() {
                    marks.push(RoundMark::Started);
                }
                self.open.push(hsdir);
                marks
            }
            HsDescAction::Uploaded => self.close(hsdir, true),
            HsDescAction::Failed if event.descriptor_id.is_none() => self.close(hsdir, false),
            _ => Vec::new(),
        }
    }

    fn close(&mut self, hsdir: RelayFingerprint, succeeded: bool) -> Vec<RoundMark> {
        let Some(at) = self.open.iter().position(|open| *open == hsdir) else {
            return Vec::new();
        };
        self.open.swap_remove(at);
        let mut marks = Vec::new();
        if succeeded {
            self.uploaded += 1;
            if !self.triggered {
                self.triggered = true;
                marks.push(RoundMark::FirstUploaded);
            }
        } else {
            self.failed += 1;
        }
        if self.open.is_empty() {
            marks.push(self.end());
        }
        marks
    }

    /// End the open round now, after the event sink dropped events: the ends that were
    /// lost will not arrive, and the next round must be able to trigger. `None` when no
    /// round is open.
    pub fn resync(&mut self) -> Option<RoundMark> {
        self.in_round().then(|| self.end())
    }

    /// Report the open round as ended and start counting the next from nothing.
    fn end(&mut self) -> RoundMark {
        let mark = RoundMark::Ended {
            uploaded: self.uploaded,
            failed: self.failed,
            unfinished: u32::try_from(self.open.len()).unwrap_or(u32::MAX),
        };
        self.open.clear();
        self.uploaded = 0;
        self.failed = 0;
        self.triggered = false;
        mark
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The throwaway onion of the 2026-10-16 capture (`DiscardPK`; the key is gone).
    const CAPTURED_ONION: &str = "url5xrvawpg5uv275sjyo6w57vvzopdufb7ffykiqnnqxjwecsxm3lid";

    /// A `650` event reply holding `line` (the status already stripped, as the framer
    /// leaves it).
    fn event(line: &str) -> TorEvent {
        let mut framer = super::super::framing::ReplyFramer::default();
        framer.push_bytes(format!("650 {line}\r\n").as_bytes());
        let reply = framer
            .next_reply()
            .expect("frames")
            .expect("one complete reply");
        parse_event(&reply).expect("a 650 event")
    }

    fn general(line: &str) -> (Severity, GeneralStatus) {
        match event(line) {
            TorEvent::General { severity, status } => (severity, status),
            other => panic!("not STATUS_GENERAL: {other:?}"),
        }
    }

    fn client(line: &str) -> (Severity, ClientStatus) {
        match event(line) {
            TorEvent::Client { severity, status } => (severity, status),
            other => panic!("not STATUS_CLIENT: {other:?}"),
        }
    }

    fn hs_desc_event(line: &str) -> HsDescEvent {
        match event(line) {
            TorEvent::HsDesc(desc) => desc,
            other => panic!("not HS_DESC: {other:?}"),
        }
    }

    #[test]
    fn a_command_reply_is_not_an_event() {
        let mut framer = super::super::framing::ReplyFramer::default();
        framer.push_bytes(b"250 OK\r\n");
        let reply = framer.next_reply().expect("frames").expect("a reply");
        assert_eq!(parse_event(&reply), None);
    }

    #[test]
    fn the_subscription_is_the_designs_list() {
        let Command::SetEvents(events) = Command::supervisor_events() else {
            panic!("not SETEVENTS");
        };
        assert_eq!(
            events,
            [
                "STATUS_GENERAL",
                "STATUS_CLIENT",
                "HS_DESC",
                "NETWORK_LIVENESS",
                "NOTICE",
                "WARN",
                "ERR"
            ]
        );
        assert_eq!(
            Command::supervisor_events()
                .to_wire()
                .expect("renders")
                .as_str(),
            "SETEVENTS STATUS_GENERAL STATUS_CLIENT HS_DESC NETWORK_LIVENESS NOTICE WARN ERR"
        );
    }

    // --- Captured from tor 0.4.9.13 (git-3c575400909efe65), 2026-10-16 ---------

    #[test]
    fn captured_bootstrap_progress() {
        let (severity, status) =
            client("STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"");
        assert_eq!(severity, Severity::Notice);
        assert_eq!(
            status,
            ClientStatus::Bootstrap(Bootstrap {
                progress: Some(100),
                tag: Some("done".to_owned()),
                problem: None,
            })
        );
    }

    /// The dead-proxy run: from the tenth problem at a phase tor recommends `warn`.
    /// `REASON`, `COUNT` and `RECOMMENDATION` come after two quoted values.
    #[test]
    fn captured_bootstrap_problem() {
        let (severity, status) = client(
            "STATUS_CLIENT WARN BOOTSTRAP PROGRESS=3 TAG=conn_proxy \
             SUMMARY=\"Connecting to proxy\" WARNING=\"Connection refused\" \
             REASON=CONNECTREFUSED COUNT=10 RECOMMENDATION=warn \
             HOSTID=\"24E2F139121D4394C54B5BCC368B3B411857C413\" \
             HOSTADDR=\"204.13.164.118:443\"",
        );
        assert_eq!(severity, Severity::Warn);
        assert_eq!(
            status,
            ClientStatus::Bootstrap(Bootstrap {
                progress: Some(3),
                tag: Some("conn_proxy".to_owned()),
                problem: Some(BootstrapProblem {
                    warning: Some("Connection refused".to_owned()),
                    reason: Some("CONNECTREFUSED".to_owned()),
                    count: Some(10),
                    recommendation: Recommendation::Warn,
                }),
            })
        );
    }

    #[test]
    fn captured_client_actions() {
        assert_eq!(
            client("STATUS_CLIENT NOTICE ENOUGH_DIR_INFO").1,
            ClientStatus::EnoughDirInfo
        );
        assert_eq!(
            client("STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED").1,
            ClientStatus::CircuitEstablished
        );
        // An action outside the list is tolerated, not an error.
        assert_eq!(
            client("STATUS_CLIENT NOTICE CONSENSUS_ARRIVED").1,
            ClientStatus::Other
        );
    }

    #[test]
    fn captured_liveness_up() {
        assert_eq!(
            event("NETWORK_LIVENESS UP"),
            TorEvent::NetworkLiveness(Liveness::Up)
        );
    }

    #[test]
    fn captured_log_events() {
        assert_eq!(
            event(
                "NOTICE The current consensus contains exit nodes. Tor can build exit and \
                 internal paths."
            ),
            TorEvent::Log(LogEvent {
                severity: LogSeverity::Notice,
                message: "The current consensus contains exit nodes. Tor can build exit and \
                          internal paths."
                    .to_owned(),
            })
        );
        assert_eq!(
            event(
                "WARN The connection to the SOCKS5 proxy server at 127.0.0.1:1 just failed. \
                 Make sure that the proxy server is up and running."
            ),
            TorEvent::Log(LogEvent {
                severity: LogSeverity::Warn,
                message: "The connection to the SOCKS5 proxy server at 127.0.0.1:1 just \
                          failed. Make sure that the proxy server is up and running."
                    .to_owned(),
            })
        );
    }

    #[test]
    fn captured_hs_desc_shapes() {
        let created = hs_desc_event(&format!(
            "HS_DESC CREATED {CAPTURED_ONION} UNKNOWN UNKNOWN \
             GOkbpjFN0/2R6w08BkOWd3Zj62ZDCvu7bVmkseOLvcY"
        ));
        assert_eq!(created.action, HsDescAction::Created);
        assert_eq!(created.address, ServiceId::parse(CAPTURED_ONION));
        assert_eq!(created.hsdir, None);
        assert_eq!(
            created.descriptor_id.as_deref(),
            Some("GOkbpjFN0/2R6w08BkOWd3Zj62ZDCvu7bVmkseOLvcY")
        );

        let upload = hs_desc_event(&format!(
            "HS_DESC UPLOAD {CAPTURED_ONION} UNKNOWN \
             $E5EAA232F5DBE71006A2C72F928055325D9731AA~forest17 \
             GOkbpjFN0/2R6w08BkOWd3Zj62ZDCvu7bVmkseOLvcY \
             HSDIR_INDEX=7B6B9F738E1A94011E071F26CBA40CC372315EFBDBE100214AC91E70C5833517"
        ));
        assert_eq!(upload.action, HsDescAction::Upload);
        assert_eq!(
            upload.hsdir,
            RelayFingerprint::parse("E5EAA232F5DBE71006A2C72F928055325D9731AA")
        );
        assert!(upload.descriptor_id.is_some());

        let uploaded = hs_desc_event(&format!(
            "HS_DESC UPLOADED {CAPTURED_ONION} UNKNOWN \
             $9E67E885D46AE284534EBA3B71A2DFE13A0E4783~Torr4Tor"
        ));
        assert_eq!(uploaded.action, HsDescAction::Uploaded);
        assert_eq!(
            uploaded.hsdir,
            RelayFingerprint::parse("9E67E885D46AE284534EBA3B71A2DFE13A0E4783")
        );
        assert_eq!(
            uploaded.descriptor_id, None,
            "an upload's end has no descriptor id"
        );
        assert_eq!(uploaded.reason, None);
    }

    /// The captured first round of a new service: sixteen `UPLOAD`s (two descriptors,
    /// eight HSDirs each), then the twelve `UPLOADED`s that arrived within the capture.
    const CAPTURED_ROUND: &str = include_str!("testdata/hs_desc_round_tor_0_4_9_13.txt");

    #[test]
    fn the_captured_round_triggers_once_and_stays_open_for_the_missing_ends() {
        let address = ServiceId::parse(CAPTURED_ONION).expect("the captured address");
        let mut rounds = UploadRounds::new(address);
        let marks: Vec<RoundMark> = CAPTURED_ROUND
            .lines()
            .filter_map(|line| line.strip_prefix("650 "))
            .map(hs_desc_event)
            .flat_map(|desc| rounds.observe(&desc))
            .collect();
        assert_eq!(marks, [RoundMark::Started, RoundMark::FirstUploaded]);
        assert!(
            rounds.in_round(),
            "four of the sixteen uploads had not ended"
        );
    }

    // --- Built from tor-0.4.9.13's format strings ------------------------------

    /// `src/core/or/circuitbuild.c`: `"CLOCK_JUMPED TIME=%"PRId64" IDLE=%d"` at
    /// `LOG_WARN`, then `CIRCUIT_NOT_ESTABLISHED REASON=CLOCK_JUMPED`.
    #[test]
    fn source_clock_jumped_and_the_circuits_it_closed() {
        assert_eq!(
            general("STATUS_GENERAL WARN CLOCK_JUMPED TIME=-3600 IDLE=0"),
            (
                Severity::Warn,
                GeneralStatus::ClockJumped {
                    seconds: Some(-3600)
                }
            )
        );
        assert_eq!(
            client("STATUS_CLIENT WARN CIRCUIT_NOT_ESTABLISHED REASON=CLOCK_JUMPED").1,
            ClientStatus::CircuitNotEstablished {
                reason: Some("CLOCK_JUMPED".to_owned())
            }
        );
    }

    /// `src/core/mainloop/connection.c`: `"CLOCK_SKEW SKEW=%ld SOURCE=%s"`. The
    /// specification also allows `MIN_SKEW=`.
    #[test]
    fn source_clock_skew() {
        assert_eq!(
            general("STATUS_GENERAL WARN CLOCK_SKEW SKEW=-7200 SOURCE=DIRSERV:192.0.2.1:80").1,
            GeneralStatus::ClockSkew {
                skew: Some(ClockSkew::Measured(-7200)),
                source: Some("DIRSERV:192.0.2.1:80".to_owned()),
            }
        );
        assert_eq!(
            general("STATUS_GENERAL WARN CLOCK_SKEW SOURCE=CONSENSUS MIN_SKEW=600").1,
            GeneralStatus::ClockSkew {
                skew: Some(ClockSkew::AtLeast(600)),
                source: Some("CONSENSUS".to_owned()),
            }
        );
    }

    /// `src/feature/nodelist/networkstatus.c`:
    /// `"DANGEROUS_VERSION CURRENT=%s REASON=%s RECOMMENDED=\"%s\""`.
    #[test]
    fn source_dangerous_version() {
        assert_eq!(
            general(
                "STATUS_GENERAL WARN DANGEROUS_VERSION CURRENT=0.4.9.13 REASON=OBSOLETE \
                 RECOMMENDED=\"0.4.8.17,0.4.9.14\""
            )
            .1,
            GeneralStatus::DangerousVersion {
                reason: VersionReason::Obsolete
            }
        );
    }

    /// `src/core/mainloop/mainloop.c`: `control_event_general_error("DIR_ALL_UNREACHABLE")`,
    /// which is `ERR`; `src/core/mainloop/connection.c`:
    /// `"TOO_MANY_CONNECTIONS CURRENT=%d"`.
    #[test]
    fn source_directory_and_connection_limits() {
        assert_eq!(
            general("STATUS_GENERAL ERR DIR_ALL_UNREACHABLE"),
            (Severity::Err, GeneralStatus::DirAllUnreachable)
        );
        assert_eq!(
            general("STATUS_GENERAL WARN TOO_MANY_CONNECTIONS CURRENT=1010").1,
            GeneralStatus::TooManyConnections {
                current: Some(1010)
            }
        );
    }

    /// `src/feature/control/control_events.c`: `"650 NETWORK_LIVENESS DOWN\r\n"`, and
    /// the directory-information pair.
    #[test]
    fn source_liveness_down_and_not_enough_dir_info() {
        assert_eq!(
            event("NETWORK_LIVENESS DOWN"),
            TorEvent::NetworkLiveness(Liveness::Down)
        );
        assert_eq!(
            client("STATUS_CLIENT NOTICE NOT_ENOUGH_DIR_INFO").1,
            ClientStatus::NotEnoughDirInfo
        );
    }

    /// `control_events.c`, `control_event_hs_descriptor_upload_end`:
    /// `"650 HS_DESC %s %s UNKNOWN %s%s"` with ` REASON=%s`, and the fetch form
    /// `event_hs_descriptor_receive_end`: `"650 HS_DESC %s %s %s %s%s%s"`, which
    /// carries the descriptor id.
    #[test]
    fn source_hs_desc_failures_upload_and_fetch() {
        let upload = hs_desc_event(&format!(
            "HS_DESC FAILED {CAPTURED_ONION} UNKNOWN \
             $9E67E885D46AE284534EBA3B71A2DFE13A0E4783~Torr4Tor REASON=UPLOAD_REJECTED"
        ));
        assert_eq!(upload.action, HsDescAction::Failed);
        assert_eq!(upload.descriptor_id, None);
        assert_eq!(upload.reason.as_deref(), Some("UPLOAD_REJECTED"));

        let fetch = hs_desc_event(&format!(
            "HS_DESC FAILED {CAPTURED_ONION} NO_AUTH \
             $9E67E885D46AE284534EBA3B71A2DFE13A0E4783~Torr4Tor \
             GOkbpjFN0/2R6w08BkOWd3Zj62ZDCvu7bVmkseOLvcY REASON=NOT_FOUND"
        ));
        assert!(fetch.descriptor_id.is_some());
        assert_eq!(fetch.reason.as_deref(), Some("NOT_FOUND"));
    }

    #[test]
    fn source_err_log_and_unsubscribed_types() {
        assert_eq!(
            event("ERR Reading config failed--see warnings above."),
            TorEvent::Log(LogEvent {
                severity: LogSeverity::Err,
                message: "Reading config failed--see warnings above.".to_owned(),
            })
        );
        assert_eq!(event("CIRC 7 BUILT"), TorEvent::Unsubscribed);
    }

    // --- Tolerance and the quoted-value rule -----------------------------------

    /// A keyword planted inside a quoted value stays inside it. Every planted keyword
    /// here would change the reading if it were taken.
    #[test]
    fn a_keyword_inside_a_quoted_value_is_never_read() {
        let (_, status) = client(
            "STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=45 TAG=conn \
             SUMMARY=\"PROGRESS=99 TAG=done WARNING=x REASON=y RECOMMENDATION=warn\"",
        );
        assert_eq!(
            status,
            ClientStatus::Bootstrap(Bootstrap {
                progress: Some(45),
                tag: Some("conn".to_owned()),
                problem: None,
            })
        );
        let (_, status) = client(
            "STATUS_CLIENT WARN BOOTSTRAP PROGRESS=3 TAG=conn WARNING=\"COUNT=99 \
             RECOMMENDATION=warn\" REASON=TIMEOUT COUNT=2 RECOMMENDATION=ignore",
        );
        let ClientStatus::Bootstrap(Bootstrap {
            problem: Some(problem),
            ..
        }) = status
        else {
            panic!("a problem form");
        };
        assert_eq!(problem.count, Some(2));
        assert_eq!(problem.recommendation, Recommendation::Ignore);
        assert_eq!(
            problem.warning.as_deref(),
            Some("COUNT=99 RECOMMENDATION=warn")
        );
    }

    /// Keywords are read by name, in any order, and an unknown one is skipped.
    #[test]
    fn keywords_in_any_order_and_unknown_ones_skipped() {
        let (_, status) = client(
            "STATUS_CLIENT WARN BOOTSTRAP NEWFIELD=1 RECOMMENDATION=warn COUNT=12 \
             REASON=NOROUTE TAG=conn PROGRESS=5",
        );
        let ClientStatus::Bootstrap(bootstrap) = status else {
            panic!("bootstrap");
        };
        assert_eq!(bootstrap.progress, Some(5));
        let problem = bootstrap.problem.expect("REASON makes it a problem");
        assert_eq!(problem.reason.as_deref(), Some("NOROUTE"));
        assert_eq!(problem.count, Some(12));
        assert_eq!(problem.recommendation, Recommendation::Warn);
        assert_eq!(problem.warning, None);
    }

    #[test]
    fn a_malformed_field_is_none_not_an_error() {
        assert_eq!(
            general("STATUS_GENERAL WARN CLOCK_JUMPED TIME=soon").1,
            GeneralStatus::ClockJumped { seconds: None }
        );
        assert_eq!(
            client("STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=900").1,
            ClientStatus::Bootstrap(Bootstrap {
                progress: None,
                tag: None,
                problem: None,
            })
        );
        assert_eq!(
            general("STATUS_GENERAL NOTICE BUG REASON=\"x\""),
            (Severity::Notice, GeneralStatus::Other)
        );
        assert_eq!(
            event("NETWORK_LIVENESS SIDEWAYS"),
            TorEvent::NetworkLiveness(Liveness::Other)
        );
        let odd = hs_desc_event("HS_DESC NEWACTION UNKNOWN UNKNOWN UNKNOWN");
        assert_eq!(odd.action, HsDescAction::Other);
        assert_eq!(odd.address, None);
    }

    #[test]
    fn a_quoted_string_is_decoded() {
        assert_eq!(unquote(r#""a\"b\\c\n""#), "a\"b\\c\n");
        assert_eq!(unquote("plain"), "plain");
        assert_eq!(
            tokens(r#"A="x y" B C="\"q r\"""#),
            [
                Token {
                    key: Some("A".to_owned()),
                    value: "x y".to_owned()
                },
                Token {
                    key: None,
                    value: "B".to_owned()
                },
                Token {
                    key: Some("C".to_owned()),
                    value: "\"q r\"".to_owned()
                },
            ]
        );
    }

    // --- Rounds ----------------------------------------------------------------

    fn round_event(action: HsDescAction, hsdir: u8, descriptor: bool) -> HsDescEvent {
        HsDescEvent {
            action,
            address: ServiceId::parse(CAPTURED_ONION),
            hsdir: Some(RelayFingerprint::from_bytes([hsdir; 20])),
            descriptor_id: descriptor.then(|| "d".to_owned()),
            reason: None,
        }
    }

    #[test]
    fn a_round_ends_when_every_upload_has_ended_and_the_next_one_starts_fresh() {
        use HsDescAction::{Failed, Upload, Uploaded};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        // Two descriptors share HSDir 1: the multiset needs both ends.
        assert_eq!(
            rounds.observe(&round_event(Upload, 1, true)),
            [RoundMark::Started]
        );
        assert!(rounds.observe(&round_event(Upload, 1, true)).is_empty());
        assert!(rounds.observe(&round_event(Upload, 2, true)).is_empty());
        assert!(rounds.observe(&round_event(Failed, 2, false)).is_empty());
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 1, false)),
            [RoundMark::FirstUploaded]
        );
        // A second success in the round triggers nothing.
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 1, false)),
            [RoundMark::Ended {
                uploaded: 2,
                failed: 1,
                unfinished: 0
            }]
        );
        assert!(!rounds.in_round());
        // The next round counts from zero and triggers again.
        assert_eq!(
            rounds.observe(&round_event(Upload, 3, true)),
            [RoundMark::Started]
        );
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 3, false)),
            [
                RoundMark::FirstUploaded,
                RoundMark::Ended {
                    uploaded: 1,
                    failed: 0,
                    unfinished: 0
                }
            ]
        );
    }

    #[test]
    fn a_round_with_no_success_ends_with_none_uploaded() {
        use HsDescAction::{Failed, Upload};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        rounds.observe(&round_event(Upload, 1, true));
        assert_eq!(
            rounds.observe(&round_event(Failed, 1, false)),
            [RoundMark::Ended {
                uploaded: 0,
                failed: 1,
                unfinished: 0
            }]
        );
    }

    /// An upload whose end never arrives does not wedge the coalescer: the next batch
    /// of uploads ends the incomplete round and can trigger again (Copilot on #1091).
    #[test]
    fn an_incomplete_round_ends_at_the_next_batch_and_the_next_round_triggers() {
        use HsDescAction::{Upload, Uploaded};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        assert_eq!(
            rounds.observe(&round_event(Upload, 1, true)),
            [RoundMark::Started]
        );
        assert!(rounds.observe(&round_event(Upload, 2, true)).is_empty());
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 1, false)),
            [RoundMark::FirstUploaded]
        );
        // HSDir 2 never reports. The next round's first upload ends this one.
        assert_eq!(
            rounds.observe(&round_event(Upload, 3, true)),
            [
                RoundMark::Ended {
                    uploaded: 1,
                    failed: 0,
                    unfinished: 1
                },
                RoundMark::Started
            ]
        );
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 3, false)),
            [
                RoundMark::FirstUploaded,
                RoundMark::Ended {
                    uploaded: 1,
                    failed: 0,
                    unfinished: 0
                }
            ]
        );
    }

    /// After the sink drops events, `resync` ends the open round at once, and the next
    /// batch starts a round that triggers. Nothing is open after it.
    #[test]
    fn resync_ends_a_round_whose_ends_were_lost() {
        use HsDescAction::{Upload, Uploaded};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        assert_eq!(rounds.resync(), None, "nothing open");
        rounds.observe(&round_event(Upload, 1, true));
        rounds.observe(&round_event(Upload, 2, true));
        assert_eq!(
            rounds.resync(),
            Some(RoundMark::Ended {
                uploaded: 0,
                failed: 0,
                unfinished: 2
            })
        );
        assert!(!rounds.in_round());
        assert_eq!(
            rounds.observe(&round_event(Upload, 1, true)),
            [RoundMark::Started]
        );
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 1, false)),
            [
                RoundMark::FirstUploaded,
                RoundMark::Ended {
                    uploaded: 1,
                    failed: 0,
                    unfinished: 0
                }
            ]
        );
    }

    /// `PROGRESS=` is a percentage: 100 reads, 101 and 255 are malformed, as
    /// `bootstrap::parse_bootstrap_progress` reads them (Copilot on #1091).
    #[test]
    fn progress_above_one_hundred_is_malformed() {
        for (raw, read) in [("100", Some(100)), ("101", None), ("255", None)] {
            let (_, status) = client(&format!("STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS={raw}"));
            let ClientStatus::Bootstrap(bootstrap) = status else {
                panic!("bootstrap");
            };
            assert_eq!(bootstrap.progress, read, "PROGRESS={raw}");
        }
    }

    /// A fetch's `FAILED` (it carries a descriptor id), another address's events, and
    /// an end for an HSDir with no open upload close nothing.
    #[test]
    fn only_an_uploads_own_end_closes_it() {
        use HsDescAction::{Failed, Upload, Uploaded};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        assert!(rounds.observe(&round_event(Uploaded, 9, false)).is_empty());
        rounds.observe(&round_event(Upload, 1, true));
        assert!(rounds.observe(&round_event(Failed, 1, true)).is_empty());
        let mut elsewhere = round_event(Uploaded, 1, false);
        elsewhere.address =
            ServiceId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(rounds.observe(&elsewhere).is_empty());
        assert!(rounds.in_round());
    }
}
