// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Drive every seed against the seam (in-process) and the epee host
//! (the C++ recording binary). Owns the seed list. Keeps transcripts
//! when the stacks disagree.

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::compare::{diff, run_matches_script, Run};
use crate::peer::run_peer;
use crate::script::{all_seeds, script, AfterHandshake, Script, READ_PAUSE, SEND_OVER_SETTLE};
use crate::transcript::Transcript;
use crate::Error;

const EPEE_BIND_WAIT: Duration = Duration::from_secs(5);
const HOST_WAIT_MS: u64 = 8_000;
const HOST_WAIT_BULK_MS: u64 = 20_000;
const BULK_WRITE_BYTES: usize = 1024 * 1024;
const FAIL_DIR: &str = "p2p-harness-fail";

/// How long the epee process waits for the connection to finish.
pub fn host_wait_ms(plan: &Script) -> u64 {
    if plan.after == AfterHandshake::Pause {
        return HOST_WAIT_BULK_MS;
    }
    let written: usize = plan.phases.iter().map(|phase| phase.write.len()).sum();
    if written >= BULK_WRITE_BYTES {
        HOST_WAIT_BULK_MS
    } else {
        HOST_WAIT_MS
    }
}

/// Arguments the C++ recorder takes. Durations come from this crate so the
/// epee binary does not own the seed table or the pause constants.
pub fn epee_cli_args(seed: u64, transcript: &Path, plan: &Script) -> Result<Vec<String>, Error> {
    let mut args = vec![
        seed.to_string(),
        path_to_string(transcript)?,
        "--after".to_string(),
        plan.after.as_str().to_string(),
        "--wait-ms".to_string(),
        host_wait_ms(plan).to_string(),
    ];
    match plan.after {
        AfterHandshake::Pause => {
            args.push("--pause-ms".to_string());
            args.push(millis(READ_PAUSE)?.to_string());
        }
        AfterHandshake::SendOver => {
            args.push("--settle-ms".to_string());
            args.push(millis(SEND_OVER_SETTLE)?.to_string());
            args.push("--over-bytes".to_string());
            args.push((crate::script::SEND_QUEUE_BYTES + 1).to_string());
        }
        AfterHandshake::None | AfterHandshake::Follow => {}
    }
    Ok(args)
}

/// Run every seed against both hosts. A mismatch keeps the four transcripts
/// under `p2p-harness-fail/seed-N/` in the current directory.
pub fn run_all(epee_bin: &Path) -> Result<(), Error> {
    if !epee_bin.is_file() {
        return Err(Error::new(format!(
            "missing epee-host: {}",
            epee_bin.display()
        )));
    }
    let seeds = all_seeds();
    if seeds.is_empty() {
        return Err(Error::new("no harness seeds"));
    }
    for seed in seeds {
        run_one(epee_bin, seed)?;
    }
    Ok(())
}

fn run_one(epee_bin: &Path, seed: u64) -> Result<(), Error> {
    let keep = PathBuf::from(FAIL_DIR).join(format!("seed-{seed}"));
    fs::create_dir_all(&keep)?;
    let seam_thread = thread::spawn(move || crate::run_seam(seed));
    let epee = run_against_epee(epee_bin, seed, &keep);
    let seam = seam_thread
        .join()
        .map_err(|_| Error::new(format!("seed {seed}: seam thread")))?;
    match (seam, epee) {
        (Ok(seam_run), Ok(epee_run)) => {
            let plan = script(seed)?;
            seam_run.peer.write(&keep.join("seam-peer.txt"))?;
            seam_run.host.write(&keep.join("seam-host.txt"))?;
            if !run_matches_script(&seam_run, &plan) {
                return Err(Error::new(format!(
                    "seed {seed}: seam does not match the script; transcripts in {}",
                    keep.display()
                )));
            }
            let findings = diff(&seam_run, &epee_run);
            if findings.is_empty() {
                drop(fs::remove_dir_all(&keep));
                return Ok(());
            }
            for finding in &findings {
                eprintln!("{finding}");
            }
            Err(Error::new(format!(
                "seed {seed}: hosts differ; transcripts in {}",
                keep.display()
            )))
        }
        (Err(seam_err), Err(epee_err)) => Err(Error::new(format!(
            "seed {seed}: seam: {seam_err}; epee: {epee_err}"
        ))),
        (Err(seam_err), Ok(_)) => Err(Error::new(format!("seed {seed}: seam: {seam_err}"))),
        (Ok(_), Err(epee_err)) => Err(Error::new(format!("seed {seed}: epee: {epee_err}"))),
    }
}

fn run_against_epee(epee_bin: &Path, seed: u64, keep: &Path) -> Result<Run, Error> {
    let plan = script(seed)?;
    let host_path = keep.join("epee-host.txt");
    let peer_path = keep.join("epee-peer.txt");
    let mut host = spawn_epee(epee_bin, seed, &host_path, &plan)?;
    let peer = run_peer(host.addr, seed);
    let wait = host.wait();
    let peer = peer?;
    wait?;
    peer.write(&peer_path)?;
    let host_transcript = Transcript::read(&host_path)?;
    Ok(Run {
        peer,
        host: host_transcript,
    })
}

struct EpeeProc {
    child: Option<Child>,
    addr: SocketAddr,
}

impl EpeeProc {
    fn wait(&mut self) -> Result<(), Error> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| Error::new("epee host already waited"))?;
        let status = child.wait()?;
        if status.success() {
            Ok(())
        } else {
            let stderr = read_stderr(&mut child);
            Err(Error::new(format!("epee host exited {status}: {stderr}")))
        }
    }
}

impl Drop for EpeeProc {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            drop(child.kill());
            drop(child.wait());
        }
    }
}

fn spawn_epee(bin: &Path, seed: u64, transcript: &Path, plan: &Script) -> Result<EpeeProc, Error> {
    let args = epee_cli_args(seed, transcript, plan)?;
    let mut child = Command::new(bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| Error::new(format!("spawn epee-host: {err}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::new("epee host stdout"))?;
    let addr_line = read_addr(stdout, EPEE_BIND_WAIT).map_err(|err| {
        let stderr = read_stderr(&mut child);
        drop(child.kill());
        drop(child.wait());
        Error::new(format!(
            "seed {seed}: epee host did not bind: {err}; {stderr}"
        ))
    })?;
    let addr: SocketAddr = addr_line
        .trim()
        .parse()
        .map_err(|_| Error::new(format!("epee host address {addr_line}")))?;
    Ok(EpeeProc {
        child: Some(child),
        addr,
    })
}

fn read_addr(
    stdout: impl std::io::Read + Send + 'static,
    timeout: Duration,
) -> Result<String, Error> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                drop(tx.send(Err(Error::new("epee host closed stdout"))));
            }
            Ok(_) => {
                drop(tx.send(Ok(line)));
            }
            Err(err) => {
                drop(tx.send(Err(Error::from(err))));
            }
        }
    });
    rx.recv_timeout(timeout)
        .map_err(|_| Error::new("epee host bind timed out"))?
}

fn read_stderr(child: &mut Child) -> String {
    let Some(stderr) = child.stderr.as_mut() else {
        return String::new();
    };
    let mut out = String::new();
    drop(BufReader::new(stderr).read_line(&mut out));
    out.trim().to_string()
}

fn path_to_string(path: &Path) -> Result<String, Error> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::new("transcript path"))
}

fn millis(duration: Duration) -> Result<u64, Error> {
    u64::try_from(duration.as_millis()).map_err(|_| Error::new("duration"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::NamedSeed;
    use std::path::Path;

    fn has_flag(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2)
            .any(|pair| pair[0] == flag && pair[1] == value)
    }

    #[test]
    fn backpressure_cli_passes_pause_from_the_rust_constants() {
        let seed = NamedSeed::Backpressure.as_u64();
        let plan = script(seed).expect("script");
        let args = epee_cli_args(seed, Path::new("host.txt"), &plan).expect("args");
        let pause_ms = millis(READ_PAUSE).expect("pause").to_string();
        let wait_ms = HOST_WAIT_BULK_MS.to_string();
        assert!(has_flag(&args, "--after", AfterHandshake::Pause.as_str()));
        assert!(has_flag(&args, "--pause-ms", &pause_ms));
        assert!(has_flag(&args, "--wait-ms", &wait_ms));
    }

    #[test]
    fn send_over_cli_passes_settle_from_the_rust_constants() {
        let seed = NamedSeed::SendOver.as_u64();
        let plan = script(seed).expect("script");
        let args = epee_cli_args(seed, Path::new("host.txt"), &plan).expect("args");
        let settle_ms = millis(SEND_OVER_SETTLE).expect("settle").to_string();
        let over_bytes = (crate::script::SEND_QUEUE_BYTES + 1).to_string();
        assert!(has_flag(
            &args,
            "--after",
            AfterHandshake::SendOver.as_str()
        ));
        assert!(has_flag(&args, "--settle-ms", &settle_ms));
        assert!(has_flag(&args, "--over-bytes", &over_bytes));
    }
}
