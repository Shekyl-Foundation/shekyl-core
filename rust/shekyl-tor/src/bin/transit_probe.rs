// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `transit_probe` — the Tor-transit arm of `hop` (DAEMON_RELAY_PRIVACY.md §71).
//!
//! # What is being measured, and why the definition is the hard part
//!
//! `hop` is **receive-to-forward**: `transit + verification + scheduling`.
//! Verification is measured (§72–§85, 48 cells, both arms). Scheduling is
//! small. **Transit is the remaining term, and only its Tor arm is open** —
//! because `hop_tor − hop_clearnet = transit_tor − transit_clearnet` when
//! verification and scheduling are the same code on the same machine, which
//! they are.
//!
//! So this probe measures **one quantity**: the transit delta between
//! transports.
//!
//! ## Three things it deliberately does not measure
//!
//! **Circuit build.** A stem forward reuses a connection the relay already
//! holds open. §71.2 rejected the SP-T3 soak for exactly this: end-to-end
//! fetches include rendezvous and circuit construction, which a stem hop never
//! pays. The probe opens each connection **once** and samples on it repeatedly.
//!
//! **Application work.** No proof verification, no parsing — a byte-count
//! payload only. Verification is already measured, and folding it in here
//! would double-count it into `hop`.
//!
//! **A mean.** SPIKE-F-16 measured a 30× spread on Tor circuit latency, and
//! `S(h)` is already a tail computation, so a central estimate is the wrong
//! statistic (§66). Output is quantiles.
//!
//! # The design that answers the hardware question
//!
//! §86.1 acquitted transit under §83.4's sorting test — *"a property of the
//! path between two nodes, not of the sender's hardware"*. **That reasoning is
//! exactly true for clearnet and questionable for Tor**, because the local
//! `tor` process does onion crypto per relay layer, which is CPU on the node.
//!
//! The probe answers it without a second experiment, by measuring **both
//! transports from both machines** and comparing **deltas** rather than
//! absolutes:
//!
//! ```text
//!   delta_x86 = tor_x86 − direct_x86
//!   delta_pi  = tor_pi  − direct_pi
//!
//!   delta_pi ≈ delta_x86   →  no hardware term; §86.1's acquittal holds for Tor
//!   delta_pi >  delta_x86   →  a hardware term exists; rule 76.4 binds and the
//!                              Pi number is the spec value
//! ```
//!
//! **Differencing is what makes this valid.** The endpoint's own latency and
//! the network path cancel within an arm, so comparing deltas across arms
//! isolates the one thing that differs: local `tor` CPU.
//!
//! Both arms **must** run the same tor build — 16.0a1 / `0.4.9.3-alpha` /
//! `git-1ee22f8f9a98719d`, digests recorded in
//! `ARCHIVAL_BOND_2D2_SP_T0_TOR.md`. Mixing builds measures hardware plus tor
//! version while looking like it measures hardware, and the mismatch runs
//! *backwards*: 16.0a1 ships an **older** tor than the shipped stable pin.
//!
//! # Usage
//!
//! ```text
//! transit_probe --target <host:port> --socks <127.0.0.1:9050> \
//!               [--samples 200] [--payload 4096] [--label x86|pi]
//! ```
//!
//! The endpoint is a **parameter, not a default**: it must be reachable
//! identically from both arms and must echo. Recording which endpoint produced
//! a number is part of the result, not an aside — an unrecorded endpoint makes
//! the two arms incomparable and the finding unreproducible.

// Display only: microsecond counts are far inside f64's exact-integer range,
// and the casts below exist to print milliseconds with one decimal.
#![allow(clippy::cast_precision_loss)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// One transport's samples, in microseconds.
///
/// `u64` rather than the `u128` `Duration::as_micros` returns: a sample large
/// enough to overflow `u64` microseconds would be ~585,000 years, so the wider
/// type buys nothing and costs a lossy cast at every print.
struct Samples {
    label: &'static str,
    us: Vec<u64>,
}

impl Samples {
    /// Nearest-rank quantile on the already-sorted samples.
    ///
    /// Integer arithmetic throughout: a float index would need a truncating
    /// cast back to `usize`, and rounding a rank is exactly the kind of
    /// silent off-by-one that turns a p90 into a p89 with no way to notice.
    fn quantile(&self, num: usize, den: usize) -> u64 {
        assert!(!self.us.is_empty(), "quantile of an empty sample");
        let idx = ((self.us.len() - 1) * num) / den;
        self.us[idx]
    }

    fn report(&mut self) {
        self.us.sort_unstable();
        println!(
            "  {:<8} n={:<4} p50={:>8.1} ms  p90={:>8.1} ms  p99={:>8.1} ms  \
             min={:>7.1}  max={:>8.1}",
            self.label,
            self.us.len(),
            self.quantile(50, 100) as f64 / 1000.0,
            self.quantile(90, 100) as f64 / 1000.0,
            self.quantile(99, 100) as f64 / 1000.0,
            self.us[0] as f64 / 1000.0,
            self.us[self.us.len() - 1] as f64 / 1000.0,
        );
    }
}

/// SOCKS5 handshake + CONNECT, no auth. Written out rather than pulled in as a
/// dependency: the probe must not link anything whose own buffering could enter
/// the measured region.
fn socks5_connect(socks: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(socks)?;
    s.set_nodelay(true)?;
    // greeting: VER=5, one method, 0x00 = no auth
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp)?;
    if resp != [0x05, 0x00] {
        return Err(std::io::Error::other(format!(
            "socks5 greeting refused: {resp:?}"
        )));
    }
    // CONNECT to a DOMAINNAME, so the exit resolves — never resolve locally,
    // which would leak the lookup outside the circuit.
    let hb = host.as_bytes();
    // SOCKS5 DOMAINNAME carries a single-byte length, so a longer host is not
    // representable. Rejected rather than cast: a truncating cast would send a
    // DIFFERENT hostname than the one asked for, and the probe would faithfully
    // measure a circuit to the wrong endpoint.
    let hlen = u8::try_from(hb.len())
        .map_err(|_| std::io::Error::other(format!("host too long for SOCKS5: {} B", hb.len())))?;
    let mut req = vec![0x05, 0x01, 0x00, 0x03, hlen];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "socks5 connect failed, reply code {}",
            head[1]
        )));
    }
    // Drain the bound address so the stream is positioned at payload.
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        other => return Err(std::io::Error::other(format!("bad ATYP {other}"))),
    };
    let mut buf = vec![0u8; skip + 2];
    s.read_exact(&mut buf)?;
    Ok(s)
}

/// Sample round-trip on an ALREADY-OPEN stream.
///
/// The connection is established by the caller and reused across every sample,
/// which is the whole point: a stem forward does not pay connection setup, so
/// including it would measure a quantity `hop` never contains.
fn sample(stream: &mut TcpStream, payload: &[u8], samples: usize) -> std::io::Result<Vec<u64>> {
    let mut out = Vec::with_capacity(samples);
    let mut back = vec![0u8; payload.len()];
    for _ in 0..samples {
        let t0 = Instant::now();
        stream.write_all(payload)?;
        stream.flush()?;
        stream.read_exact(&mut back)?;
        // Saturating rather than `as`: a truncating cast on an absurd sample
        // would report a small number, which is the direction that hides a
        // stall instead of showing one.
        out.push(u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX));
    }
    Ok(out)
}

fn arg(name: &str) -> Option<String> {
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == name {
            return it.next();
        }
    }
    None
}

fn main() -> std::io::Result<()> {
    let target =
        arg("--target").expect("--target <host:port> is required and is part of the result");
    let socks = arg("--socks").unwrap_or_else(|| "127.0.0.1:9050".into());
    let samples: usize = arg("--samples").map_or(200, |v| v.parse().expect("--samples"));
    let payload_len: usize = arg("--payload").map_or(4096, |v| v.parse().expect("--payload"));
    let label = arg("--label").unwrap_or_else(|| "unlabelled".into());

    let (host, port) = target.rsplit_once(':').expect("--target must be host:port");
    let port: u16 = port.parse().expect("port");

    // Recorded with the numbers: an unlabelled run is not comparable across
    // arms, and a run whose endpoint is not stated is not reproducible.
    println!("transit_probe  arm={label}  target={target}  socks={socks}");
    println!(
        "  payload={payload_len} B   samples={samples}   (connection reused across all samples)"
    );
    println!("  tor build must match the other arm -- see ARCHIVAL_BOND_2D2_SP_T0_TOR.md");

    let payload = vec![0xABu8; payload_len];

    let mut direct = TcpStream::connect(
        (host, port)
            .to_socket_addrs()?
            .next()
            .expect("resolve target"),
    )?;
    direct.set_nodelay(true)?;
    direct.set_read_timeout(Some(Duration::from_secs(120)))?;
    let d = sample(&mut direct, &payload, samples)?;
    drop(direct.shutdown(Shutdown::Both));

    let mut tor = socks5_connect(&socks, host, port)?;
    tor.set_nodelay(true)?;
    tor.set_read_timeout(Some(Duration::from_secs(120)))?;
    let t = sample(&mut tor, &payload, samples)?;
    drop(tor.shutdown(Shutdown::Both));

    let mut ds = Samples {
        label: "direct",
        us: d,
    };
    let mut ts = Samples {
        label: "tor",
        us: t,
    };
    ds.report();
    ts.report();

    // The delta is the quantity; the absolutes are inputs to it. Reported at
    // p50 and p90 because the hardware question is about the bulk and the
    // embargo is about the tail, and they can disagree.
    let d50 = ds.quantile(50, 100) as f64 / 1000.0;
    let t50 = ts.quantile(50, 100) as f64 / 1000.0;
    let d90 = ds.quantile(90, 100) as f64 / 1000.0;
    let t90 = ts.quantile(90, 100) as f64 / 1000.0;
    println!("\n  DELTA (tor - direct), the quantity `hop` needs:");
    println!(
        "    p50 {:+8.1} ms      p90 {:+8.1} ms",
        t50 - d50,
        t90 - d90
    );
    println!(
        "\n  Compare this delta against the OTHER arm's delta, not against its\n  \
         absolutes: the endpoint's latency and the path cancel within an arm, so\n  \
         the cross-arm difference isolates local tor CPU (§86.1's open question)."
    );
    Ok(())
}
