// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DQ-T0.4 — the per-persona circuit-isolation measurement (the 2d-2 firewall's
//! network-axis proof).
//!
//! # The split (read before adding the live harness)
//!
//! This file holds the **pure trap-logic**: it takes the four circuit IDs the
//! serialized measurement captured — each *already confirmed present* — and decides
//! the verdict. It never waits on a socket, never spawns a net, never knows whether
//! the CircIDs came from a dev-box `tor` or a hermetic owned net. That isolation is
//! deliberate (per the harness-shape review):
//!
//! - **The verdict logic and the I/O wait sit on opposite sides of the seam.** The
//!   capture (dial → drain the event sink → read the attach-time CircID, with the
//!   M4 timeout) is the flaky, integration-lane part and lives in the live harness.
//!   By the time a [`CircId`] reaches here it exists; a *missing* CircID is an
//!   apparatus failure the harness raises before building [`Observations`], never a
//!   verdict — you can't construct `Observations` without all four.
//! - That split is what lets the verdict be **unit-tested deterministically**: feed
//!   it CircID quartets, assert the positive-control / invariant verdicts, no Tor.
//!
//! The live harness (serialized dials over a real SOCKS port, the warm-up
//! apparatus-assert, the owned-net behind its own module) lives in [`mod@live`]
//! below — `#[ignore]`d, produces `Observations`, and calls [`evaluate`]. It never
//! touches the four fields directly except to build the one `Observations` the
//! verdict reads, keeping this seam intact.

use shekyl_tor::control::CircId;

/// The four attach-time circuit IDs of the serialized measurement, each confirmed
/// present (the harness only builds this after capturing all four). All four dials
/// target the **same** address — that's what removes the target confound, and why
/// the harness must serialize them to attribute each CircID unambiguously.
struct Observations {
    /// `username_A`, first dial.
    a1: CircId,
    /// `username_A` again — the positive control (same username ⇒ same circuit).
    a2: CircId,
    /// `username_B` — a different persona.
    b: CircId,
    /// The no-auth principal model (the un-isolated baseline).
    principal: CircId,
}

/// The measurement verdict.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Positive control held *and* both isolation invariants held — the firewall's
    /// network axis is proven on this run.
    Pass,
    /// At least one check failed; the flags say which (so a failure names the broken
    /// property rather than just "not isolated").
    Fail {
        /// `a1 == a2` — same username routed over the same circuit. A miss here is
        /// usually circuit rotation (pin `MaxCircuitDirtiness`), not an isolation bug.
        positive_control: bool,
        /// `a1 != principal` — a persona's circuit differs from the principal's.
        invariant_b: bool,
        /// `a1 != b` — two distinct personas get distinct circuits.
        invariant_c: bool,
    },
}

/// Decide the verdict from four confirmed-present circuit IDs. Pure: equality
/// comparisons only, no I/O.
fn evaluate(o: &Observations) -> Verdict {
    // `a1` is persona A's circuit; the positive control confirms it is stable
    // (a1 == a2), so the invariants compare it against B and the principal.
    let positive_control = o.a1 == o.a2;
    let invariant_b = o.a1 != o.principal;
    let invariant_c = o.a1 != o.b;
    if positive_control && invariant_b && invariant_c {
        Verdict::Pass
    } else {
        Verdict::Fail {
            positive_control,
            invariant_b,
            invariant_c,
        }
    }
}

#[test]
fn all_disjoint_with_stable_persona_passes() {
    // A stable (a1==a2), and B + principal each on their own circuit.
    let obs = Observations {
        a1: CircId::new(100),
        a2: CircId::new(100),
        b: CircId::new(200),
        principal: CircId::new(300),
    };
    assert_eq!(evaluate(&obs), Verdict::Pass);
}

#[test]
fn unstable_persona_fails_the_positive_control_only() {
    // a1 != a2: the persona's own two dials took different circuits — the apparatus
    // (likely dirtiness rotation) is suspect, flagged distinctly from isolation.
    let obs = Observations {
        a1: CircId::new(100),
        a2: CircId::new(101),
        b: CircId::new(200),
        principal: CircId::new(300),
    };
    assert_eq!(
        evaluate(&obs),
        Verdict::Fail {
            positive_control: false,
            invariant_b: true,
            invariant_c: true,
        }
    );
}

#[test]
fn two_personas_sharing_a_circuit_fails_invariant_c() {
    // a1 == b: persona A and persona B landed on the same circuit — isolation broke.
    let obs = Observations {
        a1: CircId::new(100),
        a2: CircId::new(100),
        b: CircId::new(100),
        principal: CircId::new(300),
    };
    assert_eq!(
        evaluate(&obs),
        Verdict::Fail {
            positive_control: true,
            invariant_b: true,
            invariant_c: false,
        }
    );
}

#[test]
fn persona_sharing_the_principal_circuit_fails_invariant_b() {
    // a1 == principal: a persona is not isolated from the un-authed baseline.
    let obs = Observations {
        a1: CircId::new(100),
        a2: CircId::new(100),
        b: CircId::new(200),
        principal: CircId::new(100),
    };
    assert_eq!(
        evaluate(&obs),
        Verdict::Fail {
            positive_control: true,
            invariant_b: false,
            invariant_c: true,
        }
    );
}

/// The **live** DQ-T0.4 harness — the I/O side of the seam. Drives the SP-T0a actor
/// against a bootstrapped Tor, runs the four serialized persona dials, and reads each
/// attach-time `CircID` off the event sink, then hands the quartet to [`evaluate`]
/// (above). The verdict logic stays pure up there; everything flaky — sockets, a real
/// `tor`, timeouts — is quarantined here.
///
/// `#[ignore]`d (integration lane). It needs a real `tor` + `tor-gencert`, supplied
/// via `SHEKYL_TEST_TOR_BINARY` + `SHEKYL_TEST_TOR_GENCERT`; a missing binary
/// **hard-fails** when the test runs — a measurement that silently no-ops proves
/// nothing. Backed by the hermetic [`mod@live::owned_net`] here; point the same
/// `(control, socks, cookie)` seam at a dev-box `tor` for the real-network run.
mod live {
    use super::{evaluate, Observations, Verdict};
    use kameo::actor::{ActorRef, Spawn};
    use shekyl_p_transport::derive_socks_user;
    use shekyl_tor::control::{
        parse_stream_event, CircId, Command, ControlReply, EventSink, TorControl, TorControlConfig,
    };
    use shekyl_types::PCanonicalId;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    /// The one fixed dial target shared by all four measured dials. Holding the
    /// *target* constant is what lets a `CircID` difference be attributed to the SOCKS
    /// username alone (Pin 1) — the harness also filters captured events to exactly
    /// this target, dropping background directory streams.
    ///
    /// **Exit-circuit-as-scaffold, not a transport path (read before "why an exit?"):**
    /// a SOCKS dial builds a general-purpose **exit** circuit — the cheapest circuit
    /// that makes per-username isolation observable. The destination is irrelevant and
    /// the dial is **expected to fail**: the `CircID` is captured at `SENTCONNECT`
    /// (Tor has chosen the circuit and sent `BEGIN`), *before* the exit ever connects.
    /// The isolation measured this way is a property of the SOCKS port's per-username
    /// circuit *selection*, not of where the circuit terminates, so the result carries
    /// to onion circuits unchanged — which is why an exit is the right (cheapest)
    /// probe even though production peer transport is **onion-to-onion** (SP-T3) and
    /// never builds an exit circuit. `192.0.2.1` is RFC 5737 TEST-NET-1: **non-private**
    /// (so the exit policy permits attach → `SENTCONNECT` fires) yet **unroutable** (so
    /// the dial fails after attach, never touching a real host). The onion-route
    /// end-to-end validation is a separate, SP-T3-owned test (see `FOLLOWUPS`).
    const TARGET: &str = "192.0.2.1:80";
    const TARGET_IP: [u8; 4] = [192, 0, 2, 1];
    const TARGET_PORT: u16 = 80;

    /// Bootstrap-gate budget (TestingTorNetwork settles in ~20-50s; a real client up
    /// to ~a minute).
    const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(150);
    /// Per-dial capture budget — long enough to build the first exit circuit then
    /// attach a stream to it.
    const CAPTURE_TIMEOUT: Duration = Duration::from_secs(60);

    /// An **apparatus** failure — the rig could not produce a clean observation. Kept
    /// deliberately distinct from a [`Verdict`]: a missing `CircID` is never "not
    /// isolated", it is "the measurement did not run", so it fails the test loudly
    /// here and never reaches `evaluate` to masquerade as a verdict.
    // The payloads are diagnostic: they are surfaced via `Debug` in the test panic
    // when the rig fails (so a failure names *which* apparatus broke), which the
    // dead-code lint cannot see through a derived `Debug`. Same pattern as the actor's
    // SP-T0b seam fields.
    #[derive(Debug)]
    #[allow(dead_code)]
    enum Apparatus {
        /// A control command failed (mailbox/transport).
        Control(String),
        /// Bootstrap did not reach 100% within budget.
        Bootstrap,
        /// No `SENTCONNECT` to the target arrived within the capture budget.
        Capture(&'static str),
        /// The actor's event sink closed (the actor stopped) mid-capture.
        ActorGone(&'static str),
    }

    /// Drive one SOCKS5 dial through the `CONNECT` request so Tor creates the stream
    /// and attaches it to a circuit (emitting `SENTCONNECT`). `auth = Some(user)`
    /// exercises `IsolateSOCKSAuth` (username/password method); `None` is the
    /// principal's no-auth baseline. We never read the `CONNECT` reply — the `CircID`
    /// is read off the control port's event sink — so the task simply holds the socket
    /// open until the caller aborts it.
    async fn socks_dial(socks: SocketAddr, auth: Option<String>) -> std::io::Result<()> {
        let mut s = TcpStream::connect(socks).await?;
        match auth {
            Some(user) => {
                // Offer *only* username/password (method 0x02), forcing the username
                // onto the wire — the field IsolateSOCKSAuth isolates on.
                s.write_all(&[0x05, 0x01, 0x02]).await?;
                let mut method = [0u8; 2];
                s.read_exact(&mut method).await?;
                let ub = user.as_bytes();
                let ulen = u8::try_from(ub.len()).expect("SOCKS username <= 255 bytes");
                // RFC 1929: version, ulen, username, plen(=0), (empty password). Tor
                // isolates on the username and ignores the password.
                let mut auth_msg = Vec::with_capacity(3 + ub.len());
                auth_msg.extend_from_slice(&[0x01, ulen]);
                auth_msg.extend_from_slice(ub);
                auth_msg.push(0x00);
                s.write_all(&auth_msg).await?;
                let mut status = [0u8; 2];
                s.read_exact(&mut status).await?;
            }
            None => {
                s.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut method = [0u8; 2];
                s.read_exact(&mut method).await?;
            }
        }
        // CONNECT, IPv4 (atyp 0x01) — sending this is what makes Tor create + attach
        // the stream; SENTCONNECT follows on the control port.
        let mut req = Vec::with_capacity(10);
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
        req.extend_from_slice(&TARGET_IP);
        req.extend_from_slice(&TARGET_PORT.to_be_bytes());
        s.write_all(&req).await?;
        // Hold the socket open and park until the caller aborts this task. We never
        // read the CONNECT reply — the CircID is read off the control port's event
        // sink at SENTCONNECT, which fires long before the (failing) exit connect would
        // produce a reply here — so keeping `s` alive is the only job left.
        std::future::pending::<std::io::Result<()>>().await
    }

    /// Dial once and read the attach-time `CircID` from the event sink. **Serialized:**
    /// the caller runs exactly one of these at a time and the sink is drained first, so
    /// the next `SENTCONNECT` to [`TARGET`] is unambiguously *this* dial's.
    async fn capture_dial(
        socks: SocketAddr,
        auth: Option<String>,
        rx: &mut mpsc::UnboundedReceiver<ControlReply>,
    ) -> Result<CircId, Apparatus> {
        // Drop residue from the prior dial so the next attach is attributed correctly.
        while rx.try_recv().is_ok() {}
        let dialer = tokio::spawn(socks_dial(socks, auth));
        let captured = timeout(CAPTURE_TIMEOUT, async {
            loop {
                match rx.recv().await {
                    Some(reply) => {
                        if let Some(ev) = parse_stream_event(&reply) {
                            if ev.status().is_sent_connect() && ev.target() == TARGET {
                                return Some(ev.circ_id());
                            }
                        }
                    }
                    // The actor dropped its EventSink sender — it stopped.
                    None => return None,
                }
            }
        })
        .await;
        dialer.abort();
        match captured {
            Ok(Some(c)) => Ok(c),
            Ok(None) => Err(Apparatus::ActorGone("event sink closed before SENTCONNECT")),
            Err(_) => Err(Apparatus::Capture(
                "no SENTCONNECT to the target within budget",
            )),
        }
    }

    /// Poll `GETINFO status/bootstrap-phase` until `PROGRESS=100`. This is the
    /// measurement's **own** bootstrap gate (its apparatus): the SP-T0b readiness
    /// `watch` (design §3b) lands later, so until then the harness gates here — a dial
    /// must never attach to a half-built network and read a meaningless circuit.
    async fn wait_for_bootstrap(actor: &ActorRef<TorControl>) -> Result<(), Apparatus> {
        let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
        loop {
            let reply = actor
                .ask(Command::GetInfo(vec!["status/bootstrap-phase".to_owned()]))
                .await
                .map_err(|e| Apparatus::Control(format!("{e:?}")))?;
            if reply.lines().iter().any(|l| l.contains("PROGRESS=100")) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Apparatus::Bootstrap);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// The full measurement over the seam `(control_addr, socks_addr, cookie_path)`:
    /// bootstrap-gate, subscribe to `STREAM`, a warm-up apparatus-assert, then the four
    /// serialized dials. Returns [`Observations`] only if all four `CircID`s were
    /// captured; any apparatus failure short-circuits before `evaluate` is reached.
    async fn measure(
        control_addr: SocketAddr,
        socks_addr: SocketAddr,
        cookie_path: &Path,
    ) -> Result<Observations, Apparatus> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let actor = TorControl::spawn(TorControlConfig {
            control_addr,
            cookie_path: cookie_path.to_path_buf(),
            events: EventSink::new(tx),
        });

        wait_for_bootstrap(&actor).await?;

        // Subscribe to STREAM only. Pre-SP-T0b the actor does not subscribe
        // STATUS_CLIENT, so a bare STREAM is correct here; once SP-T0b owns the
        // bootstrap feed, the §3b SETEVENTS-union invariant applies and this must
        // become `SETEVENTS STREAM STATUS_CLIENT` (SETEVENTS replaces, never adds).
        actor
            .ask(Command::SetEvents(vec!["STREAM".to_owned()]))
            .await
            .map_err(|e| Apparatus::Control(format!("{e:?}")))?;

        // Warm-up apparatus-assert: prove dial -> attach -> CircID works *before*
        // measuring. A miss here is a broken rig (surfaced as Apparatus), never a
        // verdict; its own circuit is discarded.
        let _warm = capture_dial(socks_addr, Some("warmup".to_owned()), &mut rx).await?;

        // The real personas: the production usernames, so this proves the actual
        // firewall identities isolate — not stand-ins.
        let user_a = derive_socks_user(&PCanonicalId::from_bytes([0x0A; 32]))
            .as_str()
            .to_owned();
        let user_b = derive_socks_user(&PCanonicalId::from_bytes([0x0B; 32]))
            .as_str()
            .to_owned();

        let a1 = capture_dial(socks_addr, Some(user_a.clone()), &mut rx).await?;
        let a2 = capture_dial(socks_addr, Some(user_a), &mut rx).await?;
        let b = capture_dial(socks_addr, Some(user_b), &mut rx).await?;
        let principal = capture_dial(socks_addr, None, &mut rx).await?;

        Ok(Observations {
            a1,
            a2,
            b,
            principal,
        })
    }

    #[tokio::test]
    #[ignore = "requires SHEKYL_TEST_TOR_BINARY + SHEKYL_TEST_TOR_GENCERT (integration lane)"]
    async fn measures_per_persona_circuit_isolation() {
        let net = owned_net::spawn().await;
        let obs = measure(net.control_addr, net.socks_addr, &net.cookie_path)
            .await
            .expect("the rig captured four attach-time circuit observations");
        assert_eq!(
            evaluate(&obs),
            Verdict::Pass,
            "per-persona circuit isolation must hold (IsolateSOCKSAuth)",
        );
    }

    /// The hermetic Tor net behind the seam — **its own module**, so the measurement
    /// logic above depends only on the three address/path values it returns, never on
    /// how the net is stood up. A no-python translation of the proven owned-net recipe
    /// (3 authority+relay+exit nodes + 1 client); the dev-box run swaps this whole
    /// module for a real `tor`. The `EnforceDistinctSubnets 0` / high
    /// `MaxCircuitDirtiness` pins are correctness assertions, not tuning: the first
    /// lets multi-hop exit circuits form on a single-host net; the second keeps a
    /// persona's two dials on one circuit so the positive control (a1 == a2) is real.
    mod owned_net {
        use std::collections::HashMap;
        use std::io::Write;
        use std::net::{SocketAddr, TcpListener};
        use std::path::{Path, PathBuf};
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        /// A spawned hermetic net. The client's `(control_addr, socks_addr,
        /// cookie_path)` is the measurement seam; every node is killed on drop.
        pub struct OwnedNet {
            children: Vec<Child>,
            _dir: tempfile::TempDir,
            pub control_addr: SocketAddr,
            pub socks_addr: SocketAddr,
            pub cookie_path: PathBuf,
        }

        impl Drop for OwnedNet {
            fn drop(&mut self) {
                for c in &mut self.children {
                    c.kill().ok();
                    c.wait().ok();
                }
            }
        }

        fn tor_binary() -> PathBuf {
            std::env::var("SHEKYL_TEST_TOR_BINARY")
                .map(PathBuf::from)
                .expect("SHEKYL_TEST_TOR_BINARY must point at a tor binary on the integration lane")
        }

        fn gencert_binary() -> PathBuf {
            std::env::var("SHEKYL_TEST_TOR_GENCERT").map(PathBuf::from).expect(
                "SHEKYL_TEST_TOR_GENCERT must point at a tor-gencert binary on the integration lane",
            )
        }

        /// Reserve `n` distinct free loopback ports. All listeners are held at once
        /// (so the ports differ) then dropped together; a small TOCTOU window before
        /// `tor` binds remains, acceptable on a test box and caught by the bootstrap
        /// timeout if a port is lost.
        fn reserve_ports(n: usize) -> Vec<u16> {
            let listeners: Vec<TcpListener> = (0..n)
                .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind ephemeral"))
                .collect();
            listeners
                .iter()
                .map(|l| l.local_addr().expect("local_addr").port())
                .collect()
            // listeners dropped here, freeing the ports for tor.
        }

        /// Spawn the net off the runtime (process spawning + the bootstrap poll block).
        pub async fn spawn() -> OwnedNet {
            tokio::task::spawn_blocking(spawn_blocking)
                .await
                .expect("owned-net setup task did not panic")
        }

        fn spawn_blocking() -> OwnedNet {
            let tor = tor_binary();
            let gencert = gencert_binary();
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path();
            let auths = ["a1", "a2", "a3"];

            // Reserve all ports up front: Phase 1 bakes each DirPort into its cert.
            let ports = reserve_ports(auths.len() * 2 + 2);
            let mut or_port = HashMap::new();
            let mut dir_port = HashMap::new();
            for (i, a) in auths.iter().enumerate() {
                or_port.insert(*a, ports[i]);
                dir_port.insert(*a, ports[auths.len() + i]);
            }
            let client_socks = ports[auths.len() * 2];
            let client_ctrl = ports[auths.len() * 2 + 1];

            // Phase 1: per-auth router fingerprint + v3 identity certificate.
            let mut fpr = HashMap::new();
            let mut v3id = HashMap::new();
            for a in auths {
                let d = root.join(a);
                std::fs::create_dir_all(d.join("keys")).expect("auth keydir");
                let out = Command::new(&tor)
                    .arg("--datadirectory")
                    .arg(&d)
                    .args(["--orport", "1", "--nickname", a, "--list-fingerprint"])
                    .output()
                    .expect("tor --list-fingerprint");
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Last stdout line is "<nick> <fingerprint>"; keep the hex after the
                // nickname (Tor may group it), expect exactly 40 hex digits.
                let fp: String = stdout
                    .lines()
                    .last()
                    .map(|l| {
                        l.split_whitespace()
                            .skip(1)
                            .flat_map(|t| t.chars())
                            .filter(char::is_ascii_hexdigit)
                            .collect()
                    })
                    .unwrap_or_default();
                assert_eq!(fp.len(), 40, "router fingerprint for {a}: {stdout}");
                fpr.insert(a, fp);

                let cert = d.join("keys").join("authority_certificate");
                let mut child = Command::new(&gencert)
                    .args(["--create-identity-key", "--passphrase-fd", "0"])
                    .arg("-i")
                    .arg(d.join("keys").join("authority_identity_key"))
                    .arg("-s")
                    .arg(d.join("keys").join("authority_signing_key"))
                    .arg("-c")
                    .arg(&cert)
                    .args(["-m", "12"])
                    .arg("-a")
                    .arg(format!("127.0.0.1:{}", dir_port[a]))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn tor-gencert");
                child
                    .stdin
                    .take()
                    .expect("gencert stdin")
                    .write_all(b"prototest\n")
                    .expect("write gencert passphrase");
                assert!(
                    child.wait().expect("gencert wait").success(),
                    "tor-gencert failed for {a}"
                );
                let cert_txt = std::fs::read_to_string(&cert).expect("read cert");
                let v3 = cert_txt
                    .lines()
                    .find_map(|l| l.strip_prefix("fingerprint "))
                    .map(|s| s.trim().to_owned())
                    .unwrap_or_else(|| panic!("no v3ident in cert for {a}"));
                v3id.insert(a, v3);
            }

            // Phase 2: the DirAuthority block shared by every torrc.
            let mut dirauth = String::new();
            for a in auths {
                dirauth.push_str(&format!(
                    "DirAuthority {a} orport={} v3ident={} 127.0.0.1:{} {}\n",
                    or_port[a], v3id[a], dir_port[a], fpr[a]
                ));
            }

            let mut children = Vec::new();
            for a in auths {
                let d = root.join(a);
                let torrc = format!(
                    "{common}\
                     AuthoritativeDirectory 1\n\
                     V3AuthoritativeDirectory 1\n\
                     AssumeReachable 1\n\
                     TestingV3AuthInitialVotingInterval 20\n\
                     TestingV3AuthInitialVoteDelay 4\n\
                     TestingV3AuthInitialDistDelay 4\n\
                     V3AuthVotingInterval 20\n\
                     V3AuthVoteDelay 4\n\
                     V3AuthDistDelay 4\n\
                     SocksPort 0\n\
                     ControlPort 0\n\
                     OrPort 127.0.0.1:{or}\n\
                     DirPort 127.0.0.1:{dp}\n\
                     Address 127.0.0.1\n\
                     ExitRelay 1\n\
                     ExitPolicyRejectPrivate 0\n\
                     ExitPolicy accept *:*\n",
                    common = common_torrc(&d, a, &dirauth),
                    or = or_port[a],
                    dp = dir_port[a],
                );
                std::fs::write(d.join("torrc"), torrc).expect("write auth torrc");
                children.push(start_tor(&tor, &d));
            }

            let cd = root.join("client");
            std::fs::create_dir_all(&cd).expect("client dir");
            let client_torrc = format!(
                "{common}\
                 SocksPort 127.0.0.1:{socks}\n\
                 ControlPort 127.0.0.1:{ctrl}\n",
                common = common_torrc(&cd, "client", &dirauth),
                socks = client_socks,
                ctrl = client_ctrl,
            );
            std::fs::write(cd.join("torrc"), client_torrc).expect("write client torrc");
            children.push(start_tor(&tor, &cd));

            // Wait for the client to bootstrap 100% (TestingTorNetwork ~20-50s).
            let notice = cd.join("notice.log");
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                if std::fs::read_to_string(&notice)
                    .map(|s| s.contains("Bootstrapped 100"))
                    .unwrap_or(false)
                {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "owned-net client did not bootstrap to 100% in time"
                );
                std::thread::sleep(Duration::from_millis(500));
            }

            OwnedNet {
                children,
                _dir: dir,
                control_addr: SocketAddr::from(([127, 0, 0, 1], client_ctrl)),
                socks_addr: SocketAddr::from(([127, 0, 0, 1], client_socks)),
                cookie_path: cd.join("control_auth_cookie"),
            }
        }

        /// The torrc lines every node shares (incl. the DirAuthority block). The two
        /// load-bearing pins live here: `EnforceDistinctSubnets 0` and a high
        /// `MaxCircuitDirtiness`.
        fn common_torrc(d: &Path, nick: &str, dirauth: &str) -> String {
            format!(
                "TestingTorNetwork 1\n\
                 EnforceDistinctSubnets 0\n\
                 PathsNeededToBuildCircuits 0.67\n\
                 TestingDirAuthVoteExit *\n\
                 TestingDirAuthVoteGuard *\n\
                 TestingDirAuthVoteHSDir *\n\
                 TestingMinExitFlagThreshold 0\n\
                 V3AuthNIntervalsValid 2\n\
                 DataDirectory {data}\n\
                 RunAsDaemon 0\n\
                 Nickname {nick}\n\
                 CookieAuthentication 1\n\
                 PidFile {pid}\n\
                 Log notice file {log}\n\
                 Sandbox 0\n\
                 MaxCircuitDirtiness 3600\n\
                 {dirauth}",
                data = d.display(),
                nick = nick,
                pid = d.join("pid").display(),
                log = d.join("notice.log").display(),
                dirauth = dirauth,
            )
        }

        fn start_tor(tor: &Path, d: &Path) -> Child {
            Command::new(tor)
                .arg("-f")
                .arg(d.join("torrc"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn tor node")
        }
    }
}
