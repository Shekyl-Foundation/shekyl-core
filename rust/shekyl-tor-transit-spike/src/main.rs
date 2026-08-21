// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DISPOSABLE measurement spike: **§94 Tor transit**.
//!
//! Measures `ANON_ZONE_TRANSIT_MEASURED_MS` — the *transit* term of
//! `hop = transit + verification + scheduling`, which is a property of the path
//! between two nodes. Verification is measured separately on the Pi surface and
//! must not appear here.
//!
//! # What §94.2/§94.5 froze, and how this implements it
//!
//! - **Onion-to-onion, no exit relay.** The anonymity zone addresses peers by
//!   `.onion`, so no exit appears in any topology a stem traverses (§89.5
//!   forbids substituting a clearnet-vs-exit delta).
//! - **One-way, not a round trip.** Both endpoints live in *this* process, so
//!   the clock is shared structurally rather than argued: the client stamps
//!   before the write, the server stamps after the full read, and the sample is
//!   their difference. RTT/2 was pre-registered as the inferior fallback (it
//!   assumes a path symmetry onion rendezvous does not guarantee) and is not
//!   used.
//! - **Two Tor daemons, not one.** `shekyl-sp-t3-spike` runs client and service
//!   on a single daemon; that makes both ends share a guard, which is not two
//!   distinct nodes. Two daemons cost two bootstraps and buy the right topology.
//! - **Established connection.** One SOCKS stream is opened, reachability is
//!   confirmed on it, and every sample rides it. Descriptor publication and
//!   circuit construction are apparatus, not latency.
//! - **Two payload arms, interleaved.** The modal transaction and the max
//!   admissible one, alternating rather than blocked, so both arms see the same
//!   network conditions. A single payload yields a scalar that silently embeds
//!   a shape assumption — the transit-less flood model's defect one layer along.
//! - **Send failures are logged and EXCLUDED** from the distribution (§94.2(a):
//!   that is the backstop's event, §92). A Tor stream is bound to its circuit
//!   and streams do not migrate, so the in-band-rebuild arm is *expected empty*;
//!   any sample landing there means that reasoning was wrong, which is why the
//!   failures are recorded rather than dropped.
//!
//! Output is JSONL on stdout, one object per sample, with UTC per sample so the
//! ≥8-hour time-of-day spread (§94.5(e)) is checkable from the data rather than
//! from anyone's recollection of when it ran.
//!
//! # Running the round unattended (read before you write a cron)
//!
//! §94.2(e) needs ≥5 sessions over ≥3 days, so this runs on a schedule, not by
//! hand. **The scheduler must BUILD this binary before each run, never invoke a
//! pre-built path.** A cron that called `target/release/…` directly re-ran a
//! stale pre-fix binary for a full slot after a fix had landed in source — it
//! OOMed on a bug that was already fixed, because the fix reached `git` but not
//! the artifact the scheduler ran (`cargo build --release` is incremental, so
//! build-first costs nothing when nothing changed). Record the binary's mtime
//! in each session's output so a stale run is visible in the data, not only in
//! hindsight. The runner is deliberately kept out of the repo: it is
//! machine-specific glue (absolute tor-binary and worktree paths), and a
//! committed script with a hardcoded `$HOME` is the debt rule 15/16 forbids.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kameo::actor::{ActorRef, Spawn as _};
use shekyl_tor::control::onion::{AddOnion, OnionFlags, OnionPort, OnionPow};
use shekyl_tor::control::{BootstrapReadiness, BootstrapState, Command, EventSink, TorControl};
use shekyl_tor::control::{ManagedTor, SocksPort, TorControlConfig, TorLaunch};
use shekyl_tor::onion_identity::OnionIdentity;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The modal Shekyl transaction's serialized `NOTIFY_NEW_TRANSACTIONS` size,
/// unpadded (`--pad-transactions` defaults to `false`). ~17 Tor cells.
const MODAL_BYTES: usize = 8_395;
/// The max admissible transaction's equivalent. ~33 cells. The second point is
/// what makes the size *slope* observable rather than assumed away.
const MAX_ADMISSIBLE_BYTES: usize = 16_651;

/// A **fresh** rig-only onion identity per session.
///
/// Not a secret and not derived from a wallet — the `.onion` value is
/// irrelevant to a latency measurement, and binding this rig to the persona
/// derivation would import co-activation semantics it has no business holding.
///
/// **It must be fresh, and this was learned the hard way.** A pinned seed
/// republishes the *same* address from a *new* tor instance each session, and
/// the HSDirs still hold the previous descriptor — pointing at introduction
/// points that died with the last run. The client fetches that stale
/// descriptor and every rendezvous fails with SOCKS `rep 0x06`. The first
/// session after a pinned-seed smoke run failed this way for its whole 300 s
/// reachability budget while the smoke run minutes earlier had succeeded,
/// because the smoke run was that address's first publication.
///
/// Pinning bought tidiness and nothing else. Freshness costs nothing, since
/// nothing in the measurement depends on which address it is.
fn fresh_rig_seed() -> Result<[u8; 32], String> {
    // `read_exact` of 32 bytes, NOT `fs::read`.
    //
    // `fs::read` reads to EOF, and `/dev/urandom` never reaches one: it is an
    // infinite stream. The first version of this function called it and grew to
    // **107 GB RSS** before the OOM killer took the process — which is the
    // `EXIT=137` (SIGKILL) the cron session recorded, and the reason four
    // consecutive sessions produced zero samples. Every one of those failures
    // was misread at the time as teardown, volatile storage, or a slow
    // bootstrap; instrumenting the bring-up is what finally located it, by
    // showing both daemons Ready in ~14 s and the hang landing *after* them.
    //
    // A device file that never ends turns "read the file" into "consume all
    // memory", and it is silent until the machine notices.
    use std::io::Read as _;
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("urandom open: {e}"))?;
    let mut seed = [0u8; 32];
    f.read_exact(&mut seed)
        .map_err(|e| format!("urandom read: {e}"))?;
    Ok(seed)
}

const VIRTUAL_PORT: u16 = 80;
const SAMPLE_CEILING: Duration = Duration::from_secs(120);

/// Minimal JSON string escaping for the one field that carries free text.
///
/// The session JSONL is the round's **data record** — receipts are committed
/// as artifacts — so a row that cannot be parsed is a sample that silently
/// disappears. `io::Error` text is OS- and call-site-supplied and does contain
/// quotes (this rig's own SOCKS errors interpolate `{:?}` of a byte array), and
/// the analyzer's field reader stops at the first `"`, so an unescaped quote
/// truncates the row rather than failing loudly.
fn json_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn utc_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

/// A free loopback port. Bound and released — the window before tor claims it
/// is small, and a lost race surfaces as a tor bind failure, not as a silent
/// mismeasurement.
fn free_port() -> std::io::Result<u16> {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(l.local_addr()?.port())
}

/// Bring one tor daemon up and wait for the readiness gate.
///
/// **Every state transition is logged with a label and a timestamp**, because
/// the first four sessions of this round produced zero samples and stderr said
/// only "bringing up two tor daemons" — which is consistent with at least three
/// different causes and distinguishes none of them. A plain-tor probe reaches
/// `Bootstrapped 100%` from this host, so the network is not the suspect; what
/// is unknown is whether this gate never fires, fires late, or is killed while
/// waiting. Silence answered none of that. Progress output does — and the
/// "killed while waiting" case is now its own exit: a readiness publisher that
/// goes away without a terminal state returns at once instead of being polled
/// until the deadline.
///
/// The label matters as much as the timestamps: the two daemons are brought up
/// concurrently, so unlabelled lines would interleave into something unreadable.
async fn bring_up(
    label: &'static str,
    binary: &std::path::Path,
    data_dir: std::path::PathBuf,
) -> Result<(ActorRef<TorControl>, u16), String> {
    let started = Instant::now();
    let socks_port = free_port().map_err(|e| format!("[{label}] free port: {e}"))?;
    let (readiness, mut ready_rx) = BootstrapReadiness::new();
    let verified = shekyl_tor::binary::discover_and_verify_at(binary)
        .map_err(|e| format!("[{label}] tor binary: {e}"))?;
    eprintln!("  [{label}] spawning tor, socks={socks_port}");
    let control = TorControl::spawn(TorControlConfig {
        launch: TorLaunch::Managed(ManagedTor {
            tor_binary: verified,
            data_dir,
            socks_port: SocksPort::Fixed(socks_port),
            disable_network: false,
            exit_observer: None,
        }),
        // No `SETEVENTS` is ever issued here, so the sink receives nothing;
        // `unsubscribed()` is the crate's named form of that fact, and it
        // drops rather than queues. A kept-alive `_rx` on an unbounded channel
        // would have accumulated every event routed, forever.
        events: EventSink::unsubscribed(),
        readiness,
    });
    let deadline = started + Duration::from_secs(300);
    let mut last = None;
    loop {
        // Report the state actually observed, not just the terminal one. A gate
        // that sits at Connecting{95} for five minutes and a gate that never
        // publishes anything look identical from the outside and have different
        // causes.
        // One clone, to release the watch borrow; the owned value is moved
        // into `last` at the bottom of the iteration, after the match has
        // borrowed it.
        let state = ready_rx.borrow_and_update().clone();
        let changed = last.as_ref() != Some(&state);
        if changed {
            eprintln!(
                "  [{label}] {:>4.0}s {state:?}",
                started.elapsed().as_secs_f64()
            );
        }
        match &state {
            BootstrapState::Ready => {
                eprintln!(
                    "  [{label}] ready in {:.0}s",
                    started.elapsed().as_secs_f64()
                );
                return Ok((control, socks_port));
            }
            // Terminal: the control connection died. Waiting out the deadline
            // here would report a timeout for something that already failed.
            BootstrapState::Failed => {
                return Err(format!(
                    "[{label}] control connection died mid-bootstrap after {:.0}s",
                    started.elapsed().as_secs_f64()
                ));
            }
            BootstrapState::Connecting { .. } => {}
        }
        if changed {
            last = Some(state);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "[{label}] bootstrap did not reach Ready in 300s (last state {last:?})"
            ));
        }
        // Three outcomes: a change (loop and report it), a 5s tick with no
        // change (loop and re-check the deadline), or the readiness sender
        // dropped without a terminal state — the actor is going down. The
        // third must return: `changed()` on a closed channel fails
        // immediately, so swallowing it would spin this loop hot until the
        // 300s deadline and then report a timeout for something that already
        // died (the same arm `shekyl-tor`'s own service loop takes).
        if let Ok(Err(_closed)) =
            tokio::time::timeout(Duration::from_secs(5), ready_rx.changed()).await
        {
            return Err(format!(
                "[{label}] readiness publisher dropped without a terminal state after {:.0}s \
                 (last state {last:?})",
                started.elapsed().as_secs_f64()
            ));
        }
    }
}

/// SOCKS5 `CONNECT` to `<onion>:port`, atyp 0x03 (domain name). The reply IS
/// read here, unlike `circuit_isolation`'s dial — this leg needs a usable
/// stream, not just a `SENTCONNECT` on the control port.
async fn socks_connect(socks: SocketAddr, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(socks).await?;
    s.set_nodelay(true)?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err(std::io::Error::other(format!(
            "SOCKS5 no-auth not selected (got {method:?})"
        )));
    }
    let hb = host.as_bytes();
    let hlen = u8::try_from(hb.len()).map_err(|_| std::io::Error::other("host > 255 bytes"))?;
    let mut req = Vec::with_capacity(7 + hb.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, hlen]);
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 CONNECT refused (rep {:#04x})",
            head[1]
        )));
    }
    // Drain the bound address so the stream is positioned at payload bytes.
    match head[3] {
        0x01 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut b = vec![0u8; usize::from(l[0]) + 2];
            s.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
        }
        other => {
            return Err(std::io::Error::other(format!("SOCKS5 atyp {other:#04x}")));
        }
    }
    Ok(s)
}

/// Cleanup policy, and it is NOT a drop guard on purpose.
///
/// A guard that removes the directory on every path would delete the two tor
/// data dirs — including their `notice.log` — exactly when a run failed and
/// those logs are the only evidence of why. Four runs failed during this
/// round's bring-up and their logs were what identified a poisoned onion
/// descriptor; a tidier cleanup would have thrown that away each time.
///
/// So: **removed on success, KEPT and announced on failure.** Splitting the
/// body into `run` is what makes that uniform across every early return,
/// rather than remembering to clean up at each one — which is the bug this
/// replaces, where only the happy path and one failure arm removed it.
#[tokio::main]
async fn main() -> Result<(), String> {
    let binary = std::env::var_os("SHEKYL_TEST_TOR_BINARY")
        .map(std::path::PathBuf::from)
        // Hard-fail, never skip (rule 47): a rig that quietly measures nothing
        // reports "no signal" where the truth is "no subject".
        .ok_or("SHEKYL_TEST_TOR_BINARY must point at a tor binary")?;
    let per_arm: usize = std::env::var("SHEKYL_TRANSIT_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    let root = std::env::temp_dir().join(format!("shekyl-transit-{}", utc_ms()));
    let client_dir = root.join("client");
    let service_dir = root.join("service");
    std::fs::create_dir_all(&client_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&service_dir).map_err(|e| e.to_string())?;

    let result = run(&binary, per_arm, client_dir, service_dir).await;
    match &result {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(&root);
        }
        Err(e) => eprintln!(
            "session failed ({e})\n  tor data dirs KEPT for diagnosis at {}\n  (cached-microdesc-consensus present = that daemon reached the directory;\n   absent = it never got that far. ManagedTor reports progress over the\n   control port, not a log file, so stderr above is the event record.)",
            root.display()
        ),
    }
    result
}

async fn run(
    binary: &std::path::Path,
    per_arm: usize,
    client_dir: std::path::PathBuf,
    service_dir: std::path::PathBuf,
) -> Result<(), String> {
    /* Concurrently, not sequentially. Two 300 s budgets in series is a 10-minute
    worst case, and the one session that produced an exit record was SIGKILLed
    at 8 minutes — inside that window. Running them together halves the
    wall clock and, more importantly, means a hang in one is visible against
    the other's progress rather than hiding behind it. */
    eprintln!("bringing up two tor daemons concurrently (separate guards) …");
    let (client, service) = tokio::try_join!(
        bring_up("client", binary, client_dir),
        bring_up("service", binary, service_dir)
    )?;
    let (client_tor, client_socks) = client;
    let (service_tor, _) = service;

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| e.to_string())?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;

    let identity = OnionIdentity::from_hs_id_seed(&fresh_rig_seed()?);
    let port = OnionPort::loopback(VIRTUAL_PORT, local).ok_or("listener must be loopback")?;
    let request = AddOnion::new(identity.mint_onion_key(), port, 8)
        .with_flags(OnionFlags { discard_pk: true })
        .with_pow(OnionPow::Disabled);
    let reply = service_tor
        .ask(Command::AddOnion(request))
        .await
        .map_err(|e| format!("ADD_ONION: {e}"))?;
    if reply.status() != 250 {
        return Err(format!("ADD_ONION status {}", reply.status()));
    }
    let service_id = shekyl_tor::control::onion::parse_service_id(reply.lines())
        .ok_or("ADD_ONION returned no ServiceID")?;
    let host = format!("{}.onion", service_id.as_str());

    // Server leg: stamps on FULL read, which is the arrival the measurement means.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(u64, Instant)>();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let _ = sock.set_nodelay(true);
        loop {
            let mut head = [0u8; 12];
            if sock.read_exact(&mut head).await.is_err() {
                return;
            }
            let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
            // The onion service is reachable by anyone who learns the address,
            // and a fresh random address is not a access control. A stranger
            // (or a corrupted frame) must not be able to size this allocation:
            // refuse anything larger than the biggest frame this rig sends.
            if len > MAX_ADMISSIBLE_BYTES {
                return;
            }
            let seq = u64::from_be_bytes([
                head[4], head[5], head[6], head[7], head[8], head[9], head[10], head[11],
            ]);
            let mut body = vec![0u8; len];
            if sock.read_exact(&mut body).await.is_err() {
                return;
            }
            if tx.send((seq, Instant::now())).is_err() {
                return;
            }
        }
    });

    eprintln!("dialing {host}:{VIRTUAL_PORT} (descriptor publication is apparatus, not latency) …");
    let socks: SocketAddr = ([127, 0, 0, 1], client_socks).into();
    let mut stream = {
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            match socks_connect(socks, &host, VIRTUAL_PORT).await {
                Ok(s) => break s,
                Err(e) if Instant::now() < deadline => {
                    eprintln!("  not reachable yet ({e}); retrying");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
                Err(e) => return Err(format!("service never became reachable: {e}")),
            }
        }
    };
    eprintln!("connection established; {per_arm} samples per arm, interleaved");

    let arms = [
        ("modal", MODAL_BYTES),
        ("max_admissible", MAX_ADMISSIBLE_BYTES),
    ];
    let mut seq: u64 = 0;
    for i in 0..per_arm {
        for (arm, size) in arms {
            seq += 1;
            let mut frame = Vec::with_capacity(12 + size);
            frame.extend_from_slice(&u32::try_from(size).unwrap_or(u32::MAX).to_be_bytes());
            frame.extend_from_slice(&seq.to_be_bytes());
            frame.resize(12 + size, 0xAB);

            let utc = utc_ms();
            let t0 = Instant::now();
            if let Err(e) = stream.write_all(&frame).await {
                // EXCLUDED from the distribution (§94.2(a)) but recorded: this is
                // the arm expected to stay empty.
                println!(
                    r#"{{"utc_ms":{utc},"seq":{seq},"arm":"{arm}","size_bytes":{size},"outcome":"send_failure","detail":"{}"}}"#,
                    json_escape(&e.to_string())
                );
                return Err(format!("stream died at seq {seq}: {e}"));
            }
            match tokio::time::timeout(SAMPLE_CEILING, rx.recv()).await {
                Ok(Some((got, t1))) if got == seq => {
                    let us = t1.duration_since(t0).as_micros();
                    println!(
                        r#"{{"utc_ms":{utc},"seq":{seq},"arm":"{arm}","size_bytes":{size},"outcome":"ok","one_way_us":{us}}}"#
                    );
                }
                Ok(Some((got, _))) => {
                    return Err(format!("frame ordering broke: expected {seq}, got {got}"));
                }
                Ok(None) => return Err("server leg closed".into()),
                Err(_) => {
                    println!(
                        r#"{{"utc_ms":{utc},"seq":{seq},"arm":"{arm}","size_bytes":{size},"outcome":"timeout"}}"#
                    );
                }
            }
        }
        if i % 20 == 0 {
            eprintln!("  {}/{per_arm} per arm", i + 1);
        }
    }

    drop(stream);
    drop(client_tor);
    drop(service_tor);
    Ok(())
}
