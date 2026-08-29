// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **P-17** — does the logon SID **by itself** refuse a caller from a
//! different logon session, the `IPC$` reachability WP-D6 exists for?
//!
//! Pre-registered in `WINDOWS_WALLET_PROBE_SHEET.md` §3 (corrected §3.1
//! before any run), and run by `scripts/ci/windows_probe.ps1` in **both**
//! modes — its precondition is a loopback SMB path, not an interactive
//! logon, and whether the CI runner has one is exactly the §3.1 promotion
//! question.
//!
//! # The four rows, and why each fence is lowered where it is
//!
//! Production keeps **three** fences against a foreign caller: the
//! `PIPE_REJECT_REMOTE_CLIENTS` flag, the owner-only DACL whose single ACE
//! is the logon SID, and the Medium mandatory label. A refusal with all of
//! them up attributes nothing — the P-7 lesson. So each row lowers exactly
//! the fences it is not measuring, the same move P-12 makes with
//! `without_label_for_testing`:
//!
//! | Row | Pipe | Path | Predicted |
//! |---|---|---|---|
//! | (a) control | production shape (flag + DACL + label) | `\\.\pipe\…` | opens — the DACL admits its own session |
//! | (b) mechanism | permissive (`D:(A;;GA;;;WD)`, no flag, no label) | `\\<host>\pipe\…` | opens, and the caller's logon SID **differs** from ours |
//! | (c) production | production shape | `\\<host>\pipe\…` | refused — by *some* fence; which one is deliberately not claimed |
//! | (d) the D6 claim | DACL only (no flag, no label) | `\\<host>\pipe\…` | refused with `ERROR_ACCESS_DENIED` — and now only the logon-SID ACE can be the refuser |
//!
//! Row (b) is what turns "an SMB path produces a distinct logon session"
//! from a premise into an observation: the server impersonates the caller and
//! reads the logon SID off the impersonation token. **The first run
//! (2026-08-27) falsified that premise for `\\localhost\…`** — a loopback
//! caller reuses its own token and arrives as us — so the mechanism now
//! probes each host in [`transport_hosts`] and uses the first observed to
//! cross. If none crosses, everything downstream is **UNRUN**: a refusal
//! would be unattributed, and the honest reading is that no single-box
//! transport can pose as a foreign session (§4, and the sheet's §3.1).
//!
//! **The two-machine `--serve` mode is what answered it (2026-08-28, §4.8),
//! and it reframed row (b) a second time.** A genuine remote caller over
//! `IPC$` does not carry a *different* logon SID — it carries **none at all**
//! (a network logon has no `SE_GROUP_LOGON_ID` group), so row (d) holds
//! *structurally*: a logon-SID-only ACE is unmatchable from the network, and
//! the same token's user SID — which *is* present — is what makes the refusal
//! attributable. The four-row table above is the pre-registration and stays as
//! written (§5); this is the observation that came back, on a stronger footing
//! than the prediction assumed.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |---|---|
//! | `0` | a crossing transport was found and all four rows held — the logon-SID ACE alone carries the boundary |
//! | `1` | a prediction was **falsified** — a crossing caller was *admitted* by a shape that should refuse; revisits WP-D6, see the sheet |
//! | `2` | UNRUN — no transport crossed a session boundary, or a precondition was absent; never a pass, and NOT a WP-D6 falsification |

fn main() {
    #[cfg(windows)]
    {
        std::process::exit(probe::main());
    }
    #[cfg(not(windows))]
    {
        eprintln!("P-17 is a Windows probe; this target has no pipe namespace or logon SIDs.");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod probe {
    use std::ffi::c_void;
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    use shekyl_win_sec::{
        current_logon_sid, current_user_sid, logon_sid_of_token_for_testing, self_hosted_pipe_name,
        user_sid_of_token_for_testing, OwnerOnlyDescriptor, SidError,
    };

    /// `ERROR_ACCESS_DENIED` — the (d) prediction, and the only code that row
    /// accepts: any other refusal would mean a mechanism this probe did not
    /// lower, and must be looked at rather than counted.
    const ACCESS_DENIED: u32 = 5;

    /// `SDDL_REVISION_1` — the only revision that exists.
    const SDDL_REVISION: u32 = 1;

    /// How long to wait for the loopback client thread's verdict. The open
    /// either completes or fails within the SMB connect timeout (seconds);
    /// this is a hang ceiling for the harness, not a deadline for the OS.
    const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

    /// How long `--serve` waits for the remote caller. Far longer than
    /// [`CLIENT_TIMEOUT`] because the two machines are coordinated by hand
    /// across a message relay whose per-hop latency is not under our control;
    /// racing a tight timer against that only manufactures UNRUN runs that say
    /// nothing about WP-D6. An hour turns coordination from a race into "the
    /// server is up, dial whenever" — the window's only real job is to stop a
    /// sweep run from hanging, and nothing about the measurement depends on it
    /// being tight. Still bounded, so a box that never dials cannot hang the
    /// operator indefinitely.
    const SERVE_TIMEOUT: Duration = Duration::from_secs(3600);

    /// Spawn counters, so no two pipe instances ever share a name within a run —
    /// a consumed or squatted instance must not confound a neighbouring row, and
    /// (all `transport_hosts()` resolve to THIS box, so a reused name is a reused
    /// *object*) a timed-out-then-detached mechanism client must not be able to
    /// connect to a LATER instance of the same name. The single-instance rows
    /// below take fixed counters; the mechanism survey takes a **distinct**
    /// counter per host attempt from a disjoint range ([`SPAWN_MECH_BASE`] `+
    /// host_index`), so a stalled client dialing one attempt's name cannot cross
    /// into the next attempt's — nor into a single-instance row's.
    const SPAWN_CONTROL: u64 = 1_701;
    const SPAWN_PROD: u64 = 1_702;
    const SPAWN_DACL_ONLY: u64 = 1_703;
    /// Base for the mechanism survey's per-host attempt names; the host index is
    /// added. Disjoint from 1_701–1_703 so a late detached client can never land
    /// on a single-instance row's pipe.
    const SPAWN_MECH_BASE: u64 = 1_710;

    /// Owns a raw handle; closes exactly once, on every path out — including
    /// the early-exit paths, which is what keeps a blocked peer from hanging
    /// the run (a closed server end turns the client's blocking read into an
    /// error instead of a wait).
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                // SAFETY: the guard is the sole owner of a handle that came
                // from CreateNamedPipeW/CreateFileW/OpenThreadToken.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error() -> u32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .and_then(|e| u32::try_from(e).ok())
            .unwrap_or(0)
    }

    /// `\\.\pipe\X` → `\\<host>\pipe\X`: the same pipe object, addressed
    /// through the SMB `IPC$` path under `host` instead of the local pipe
    /// namespace. The name is what changes the transport; the object is
    /// identical.
    ///
    /// `host` is `localhost` or this machine's own name — see
    /// [`transport_hosts`] for why both are tried and why neither is
    /// assumed to cross a logon-session boundary.
    fn remote_form(local: &str, host: &str) -> Option<String> {
        local
            .strip_prefix(r"\\.\pipe\")
            .map(|tail| format!(r"\\{host}\pipe\{tail}"))
    }

    /// The SMB hosts P-17 tries as cross-session transports, in order.
    ///
    /// **The first run (2026-08-27) falsified the original premise** that
    /// `\\localhost\pipe\…` produces a distinct logon session: measured, a
    /// loopback caller reuses the caller's own token and arrives with *our*
    /// logon SID. So `localhost` is kept only as the recorded control — it is
    /// known not to cross — and the machine's own name is tried as the
    /// candidate that *might*, because a connection to a name that is not
    /// `localhost`/`127.0.0.1` can take the network-provider path and land in
    /// a network logon. **That is a claim to be measured, not asserted** — the
    /// mechanism row reads the caller's logon SID for each host and only a
    /// host observed to differ from ours is used for the attribution rows.
    fn transport_hosts() -> Vec<String> {
        let mut hosts = vec!["localhost".to_owned()];
        if let Ok(name) = std::env::var("COMPUTERNAME") {
            if !name.is_empty() {
                hosts.push(name);
            }
        }
        hosts
    }

    /// Try to open `name` for read+write. `0` means it opened (the handle is
    /// closed immediately); anything else is the Win32 error.
    ///
    /// `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` is set explicitly
    /// rather than inherited from defaults: row (b)'s server must be able to
    /// impersonate this caller, and an implicit QOS level is exactly the kind
    /// of ambient fact a probe must not lean on.
    fn try_open(name: &str) -> u32 {
        let wide_name = wide(name);
        // SAFETY: `wide_name` is NUL-terminated and outlives the call.
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return last_error();
        }
        drop(HandleGuard(handle));
        0
    }

    /// Create one raw pipe instance at `name` with `attributes`, byte mode,
    /// one instance, `first_pipe_instance` — and the remote-client flag only
    /// when asked, because which fences are up is each row's whole design.
    fn create_instance(
        name: &str,
        attributes: *const SECURITY_ATTRIBUTES,
        reject_remote: bool,
    ) -> Result<HandleGuard, u32> {
        let mode = PIPE_TYPE_BYTE
            | PIPE_READMODE_BYTE
            | PIPE_WAIT
            | if reject_remote {
                PIPE_REJECT_REMOTE_CLIENTS
            } else {
                0
            };
        let wide_name = wide(name);
        // SAFETY: `wide_name` is NUL-terminated; `attributes` is either null
        // or points at a live SECURITY_ATTRIBUTES that outlives the call
        // (CreateNamedPipeW reads it only during the call).
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                mode,
                1,
                512,
                512,
                0,
                attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        Ok(HandleGuard(handle))
    }

    /// A deliberately permissive descriptor — `D:(A;;GA;;;WD)`, no label —
    /// for the mechanism pipe only.
    ///
    /// Permissive on purpose and safe on purpose: this pipe exists for
    /// milliseconds, carries one probe byte in each direction and no wallet
    /// state, and every fence must be down so that the *only* question it
    /// answers is "what identity does a loopback caller arrive with". A
    /// refusal here would be unattributable noise.
    /// A P-17 pipe name that **two machines can compute identically**, without
    /// exchanging it.
    ///
    /// Deliberately **not** [`self_hosted_pipe_name`]: that embeds the serving
    /// process's PID (`pipe.rs`, WP-D1's in-process-collision hygiene, which
    /// its own module docs mark as "not security"), which the dialling machine
    /// cannot derive — it would compute a different name, `CreateFile` would
    /// return `ERROR_FILE_NOT_FOUND`, and the run would report a refusal for a
    /// pipe never dialled (the P-7 shape). Both machines run as the same AD
    /// user, so the **user SID** is the shared component; a fixed `-p17-<role>`
    /// discriminator names the three pipes with no PID and no exchange.
    ///
    /// This is a name, not a descriptor. Rows (c)/(d) test the production
    /// **descriptor** — the DACL, label, and `reject_remote_clients` flag —
    /// which is what WP-D6 is about; production *naming* is out of scope, and
    /// dropping the PID costs the probe nothing it measures.
    fn p17_pipe_name(user_sid: &shekyl_win_sec::SidString, role: &str) -> String {
        format!(r"\\.\pipe\shekyl-wallet-{}-p17-{role}", user_sid.as_str())
    }

    /// A security descriptor built from an SDDL string, owning the allocation.
    struct SdFromSddl(*mut c_void, SECURITY_ATTRIBUTES);
    impl SdFromSddl {
        fn new(sddl: &str) -> Result<Self, u32> {
            let sddl = wide(sddl);
            let mut sd: *mut c_void = std::ptr::null_mut();
            // SAFETY: `sddl` is NUL-terminated; `sd` is written only on
            // success and freed by Drop below, per the API's LocalFree
            // contract.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION,
                    &raw mut sd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            let attrs = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            Ok(Self(sd, attrs))
        }
        fn attributes_ptr(&self) -> *const SECURITY_ATTRIBUTES {
            &raw const self.1
        }
    }
    impl Drop for SdFromSddl {
        fn drop(&mut self) {
            // SAFETY: `sd` came from the converter, which documents LocalFree.
            unsafe { LocalFree(self.0) };
        }
    }
    use std::mem::size_of;

    /// The result of reading a caller's user and logon SID off its impersonation
    /// token — shared by [`serve`] and [`mechanism_row`] so the two paths cannot
    /// drift in how they treat a network logon. `UserOkNoLogon` is broken out
    /// from the generic failure because it is not an error at all here — it is
    /// P-17's candidate answer: a caller whose token carries the user SID but no
    /// logon-SID-shaped `SE_GROUP_LOGON_ID` group, which is precisely what a
    /// network (`IPC$`) logon is expected to look like and cannot match a
    /// logon-SID-only ACE.
    enum SidTriage {
        /// Both SIDs read — the same-user / different-logon-session path.
        Both { user: String, logon: String },
        /// User SID read; the token carries no logon SID (`SidError::NoLogonSid`).
        UserOkNoLogon { user: String },
        /// A read failed for some other reason; the message names which side and
        /// the `SidError` variant (or the Win32 step that failed).
        Unreadable(String),
    }

    /// Which shape of session-crossing the single-box survey observed on the host
    /// it selected. Both are genuine crossings; they differ only in how the
    /// caller's token presents, and therefore in how the final verdict narrates
    /// the refusal — keeping the two apart is the same message-names-the-mechanism
    /// discipline the rest of this probe follows.
    enum CrossingForm {
        /// A caller carrying a *different* logon SID (terminal-services shape).
        DifferentLogonSid,
        /// A caller carrying *no* logon SID at all (network / `IPC$` shape).
        NoLogonSid,
    }

    /// The shared tail of the two same-user verdict arms: given the caller's
    /// two reported codes, attribute the refusal (or its absence) to the
    /// DACL-only ACE. Only the two SID-specific stories differ between callers,
    /// so they are passed in — `on_admit` (the DACL-only pipe *opened*: WP-D6
    /// did not hold) and `on_pass` (it refused with `ERROR_ACCESS_DENIED`: the
    /// boundary held). The production-hole FAIL and the wrong-error UNRUN are
    /// identical for both callers and live here, so a later correction to the
    /// ladder cannot drift between the different-logon-SID and no-logon-SID
    /// arms. Returns the process exit code.
    fn attribute_dacl_refusal(dacl_err: u32, prod_err: u32, on_admit: &str, on_pass: &str) -> i32 {
        if dacl_err == 0 {
            println!("{on_admit} (prod os error {prod_err})");
            return 1;
        }
        if prod_err == 0 {
            println!(
                "P-17 FAIL: the PRODUCTION pipe admitted a remote caller — a live IPC$ hole past \
                 the reject-remote flag. Revisits WP-D6, urgently. (daclonly os error {dacl_err})"
            );
            return 1;
        }
        if dacl_err != ACCESS_DENIED {
            println!(
                "P-17 UNRUN: the DACL-only open was refused with os error {dacl_err}, not \
                 ERROR_ACCESS_DENIED — some other mechanism refused it, so the ACE is not \
                 attributed. (prod os error {prod_err})"
            );
            return 2;
        }
        println!("{on_pass} (production shape refused with os error {prod_err})");
        0
    }

    /// Stands up the three pipes a remote same-user caller dials, reads the
    /// caller's identity off the impersonation token to attribute the refusal —
    /// the caller carries either a *different* logon SID (terminal-services
    /// form) or, over `IPC$`, *no* logon SID at all (§4.8) — authoritatively,
    /// not from the client's self-report, and combines that with the caller's
    /// report of which pipes refused it, which only the caller can observe
    /// (a refused open never reaches the server). The wait is bounded: a machine
    /// that never dials yields UNRUN, never a hang.
    fn serve(me: &shekyl_win_sec::SidString, my_logon: &shekyl_win_sec::SidString) -> i32 {
        // Control: granted to the USER SID (not the logon SID), no label, no
        // reject-remote flag — the remote same-user caller must open it (the
        // attribution control) and report through it.
        let control_sd = match SdFromSddl::new(&format!("D:(A;;GA;;;{})", me.as_str())) {
            Ok(sd) => sd,
            Err(e) => {
                println!("P-17 UNRUN: could not build the control descriptor (os error {e}).");
                return 2;
            }
        };
        let Ok(dacl_only) = OwnerOnlyDescriptor::without_label_for_testing(me, my_logon) else {
            println!("P-17 UNRUN: could not build the DACL-only descriptor.");
            return 2;
        };
        let Ok(production) = OwnerOnlyDescriptor::new(me, my_logon) else {
            println!("P-17 UNRUN: could not build the production descriptor.");
            return 2;
        };

        let control_name = p17_pipe_name(me, "control");
        let dacl_name = p17_pipe_name(me, "daclonly");
        let prod_name = p17_pipe_name(me, "prod");

        let control = match create_instance(&control_name, control_sd.attributes_ptr(), false) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the control pipe (os error {e}).");
                return 2;
            }
        };
        // `_dacl` / `_prod` are bound (not `_`) so the pipes stay alive across
        // the wait for the caller to attempt them; a refused open is denied at
        // `CreateFile`, so the server never accepts on these two.
        let _dacl = match create_instance(&dacl_name, dacl_only.attributes_ptr(), false) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the DACL-only pipe (os error {e}).");
                return 2;
            }
        };
        let _prod = match create_instance(&prod_name, production.attributes_ptr(), true) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the production pipe (os error {e}).");
                return 2;
            }
        };

        let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| ".".to_owned());
        let strip = |n: &str| n.strip_prefix(r"\\.\pipe\").unwrap_or(n).to_owned();
        let dial = |n: &str| format!(r"\\{host}\pipe\{}", strip(n));
        println!("P-17 SERVE ready on host {host}. The remote same-user caller, in order:");
        println!(
            "  1. open {} -> expect ERROR_ACCESS_DENIED (5)",
            dial(&dacl_name)
        );
        println!(
            "  2. open {} -> expect refused (reject-remote flag)",
            dial(&prod_name)
        );
        println!(
            "  3. open {} and write one ASCII line: \"<step1-oserr> <step2-oserr>\"",
            dial(&control_name)
        );

        // What the accept thread learned about the caller. Split so that no
        // diagnostic path discards a measurement: once the caller's report has
        // been read, its two reported codes travel with *every* downstream
        // outcome, including the ones where reading the caller's SIDs failed —
        // the earlier shape mapped codes only onto the success path, which is
        // why the 15:45:48 log recorded a SID-read failure with no trace of the
        // `5 5` the caller had actually reported.
        // `SidTriage` (the caller's SID read) is a module item now — shared with
        // `mechanism_row` so the two paths treat a no-logon-SID network caller
        // identically. `CallerOutcome` stays local: only `serve` carries the
        // caller's two reported codes alongside that triage, so that no
        // diagnostic path discards a measurement (the earlier shape mapped codes
        // only onto the success path, which is why the 15:45:48 log recorded a
        // SID-read failure with no trace of the `5 5` the caller had reported).
        enum CallerOutcome {
            /// No usable report — connect/read failed, or the report did not
            /// parse as exactly two integers; no trustworthy codes.
            NoReport(String),
            /// The report parsed; the SID triage is what happened after.
            Reported {
                dacl_err: u32,
                prod_err: u32,
                sids: SidTriage,
            },
        }

        // Accept + impersonate on a thread so the wait can be bounded. HANDLE
        // is not Send, so the raw pointer is carried across as a usize; the
        // thread reconstructs the guard and owns the close. On timeout the
        // thread is left blocked in ConnectNamedPipe and dies when the process
        // exits after the verdict.
        let (tx, rx) = mpsc::channel::<CallerOutcome>();
        let control_raw = control.0 as usize;
        std::mem::forget(control);
        std::thread::spawn(move || {
            let server = HandleGuard(control_raw as HANDLE);
            // SAFETY: our own pipe instance.
            let connected = unsafe { ConnectNamedPipe(server.0, std::ptr::null_mut()) };
            if connected == 0 && last_error() != ERROR_PIPE_CONNECTED {
                _ = tx.send(CallerOutcome::NoReport(format!(
                    "ConnectNamedPipe failed (os error {})",
                    last_error()
                )));
                return;
            }
            // Read the caller's report first — this also satisfies the
            // "server has read from the client" precondition for impersonation.
            let mut buf = [0u8; 128];
            let mut got: u32 = 0;
            // SAFETY: live handle, valid buffer.
            let read_ok = unsafe {
                ReadFile(
                    server.0,
                    buf.as_mut_ptr(),
                    128,
                    &raw mut got,
                    std::ptr::null_mut(),
                )
            };
            if read_ok == 0 || got == 0 {
                _ = tx.send(CallerOutcome::NoReport(format!(
                    "could not read the caller's report (os error {})",
                    last_error()
                )));
                return;
            }
            let report = String::from_utf8_lossy(&buf[..got as usize])
                .trim()
                .to_owned();
            // Strict parse: EXACTLY two integers, nothing substituted. A missing
            // or malformed field must not become a value the verdict can pass on
            // — a sentinel like `u32::MAX` reads as "nonzero = refused" and
            // `attribute_dacl_refusal(5, u32::MAX, ..)` would return PASS off a
            // report that never actually reported a prod refusal. A byte-mode
            // pipe gives no framing guarantee, so a split read has to degrade to
            // UNRUN, which is retryable and fail-safe, not to a false pass.
            let mut parts = report.split_whitespace();
            let parsed = match (
                parts.next().and_then(|s| s.parse::<u32>().ok()),
                parts.next().and_then(|s| s.parse::<u32>().ok()),
                parts.next(),
            ) {
                (Some(dacl), Some(prod), None) => Some((dacl, prod)),
                _ => None,
            };
            let Some((dacl_err, prod_err)) = parsed else {
                _ = tx.send(CallerOutcome::NoReport(format!(
                    "the caller's control report was not exactly two integers ({report:?}) — \
                     a refusal cannot be attributed to a report that could not be parsed"
                )));
                return;
            };
            // SAFETY: read precondition satisfied above; reverted on every path.
            let imp = unsafe { ImpersonateNamedPipeClient(server.0) };
            if imp == 0 {
                _ = tx.send(CallerOutcome::Reported {
                    dacl_err,
                    prod_err,
                    sids: SidTriage::Unreadable(format!(
                        "ImpersonateNamedPipeClient failed (os error {})",
                        last_error()
                    )),
                });
                return;
            }
            let mut token: HANDLE = std::ptr::null_mut();
            // SAFETY: current-thread pseudo-handle, OpenAsSelf=1.
            let opened =
                unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
            let token_guard = HandleGuard(token);
            let sids = if opened == 0 {
                SidTriage::Unreadable(format!(
                    "could not open the impersonation token (os error {})",
                    last_error()
                ))
            } else {
                // `{:?}` (Debug), never Display, for the variant: `SidError`'s
                // Display text for a `TokenGroups` read still names "user SID"
                // (sid.rs), which would misreport a *logon*-SID read failure as
                // a user-SID one. The variant is what the verdict below keys on.
                match (
                    user_sid_of_token_for_testing(token_guard.0),
                    logon_sid_of_token_for_testing(token_guard.0),
                ) {
                    (Ok(u), Ok(l)) => SidTriage::Both {
                        user: u.as_str().to_owned(),
                        logon: l.as_str().to_owned(),
                    },
                    // The candidate answer: user present, no logon SID at all.
                    (Ok(u), Err(SidError::NoLogonSid)) => SidTriage::UserOkNoLogon {
                        user: u.as_str().to_owned(),
                    },
                    (Err(ue), _) => SidTriage::Unreadable(format!(
                        "could not read the caller's USER SID: {ue:?}"
                    )),
                    (Ok(_), Err(le)) => SidTriage::Unreadable(format!(
                        "could not read the caller's LOGON SID: {le:?}"
                    )),
                }
            };
            // SAFETY: paired with the impersonation above.
            let reverted = unsafe { RevertToSelf() };
            if reverted == 0 {
                eprintln!("P-17: RevertToSelf FAILED — aborting rather than run impersonated.");
                std::process::abort();
            }
            _ = tx.send(CallerOutcome::Reported {
                dacl_err,
                prod_err,
                sids,
            });
        });

        match rx.recv_timeout(SERVE_TIMEOUT) {
            Err(_) => {
                println!(
                    "P-17 UNRUN: no remote caller connected within {}s. Not a pass — the second \
                     machine did not dial, or could not reach IPC$.",
                    SERVE_TIMEOUT.as_secs()
                );
                2
            }
            Ok(CallerOutcome::NoReport(detail)) => {
                println!("P-17 UNRUN: {detail}.");
                2
            }
            Ok(CallerOutcome::Reported {
                dacl_err,
                prod_err,
                sids: SidTriage::Unreadable(detail),
            }) => {
                println!(
                    "P-17 UNRUN: {detail}. The caller DID connect and its report was read — daclonly \
                     os error {dacl_err}, prod os error {prod_err} — so this is a token-read failure, \
                     not a transport failure. Not a pass."
                );
                2
            }
            Ok(CallerOutcome::Reported {
                dacl_err,
                prod_err,
                sids: SidTriage::Both { user, logon },
            }) => {
                println!("P-17 SERVE: caller user SID {user}, logon SID {logon}.");
                if user != me.as_str() {
                    println!(
                        "P-17 UNRUN: the caller is a DIFFERENT user than the server ({}). A refusal \
                         would be over-determined (they are not in the DACL at all), not attributable \
                         to the logon SID. Log the second machine in as the same AD user. (caller \
                         reported daclonly {dacl_err}, prod {prod_err})",
                        me.as_str()
                    );
                    return 2;
                }
                if logon == my_logon.as_str() {
                    println!(
                        "P-17 UNRUN: the caller shares OUR logon SID — it did not cross a session \
                         boundary. Not a pass. (caller reported daclonly {dacl_err}, prod {prod_err})"
                    );
                    return 2;
                }
                println!(
                    "P-17 SERVE: same user, different logon session — a genuine cross-session caller, \
                     observed."
                );
                attribute_dacl_refusal(
                    dacl_err,
                    prod_err,
                    "P-17 FAIL: the DACL-only pipe ADMITTED a cross-session same-user caller. The \
                     logon-SID ACE does not carry the boundary; PR #516's user-SID removal bought \
                     nothing. Revisits WP-D6.",
                    "P-17 PASS: a genuine cross-session same-user caller is refused by the logon-SID \
                     ACE alone (ERROR_ACCESS_DENIED). WP-D6's IPC$ claim is now an observation.",
                )
            }
            Ok(CallerOutcome::Reported {
                dacl_err,
                prod_err,
                sids: SidTriage::UserOkNoLogon { user },
            }) => {
                println!(
                    "P-17 SERVE: caller user SID {user}, and NO logon SID — the impersonation token \
                     carries no `SE_GROUP_LOGON_ID`-marked group of logon-SID (`S-1-5-5-…`) shape. \
                     This is the expected shape of a network (`IPC$`) logon."
                );
                if user != me.as_str() {
                    println!(
                        "P-17 UNRUN: the caller is a DIFFERENT user than the server ({}). A refusal \
                         would be over-determined (they are not in the DACL at all), not attributable \
                         to the logon-SID ACE. Log the second machine in as the same AD user. (caller \
                         reported daclonly {dacl_err}, prod {prod_err})",
                        me.as_str()
                    );
                    return 2;
                }
                attribute_dacl_refusal(
                    dacl_err,
                    prod_err,
                    "P-17 FAIL: the DACL-only pipe ADMITTED a same-user caller whose token carries no \
                     logon SID — a token that cannot match the logon-SID ACE was let in anyway. \
                     WP-D6's boundary does not hold. Revisits WP-D6.",
                    "P-17 PASS (structural): a genuine same-user caller arriving over IPC$ carries NO \
                     logon SID, so it cannot match the logon-SID-only ACE and is refused \
                     (ERROR_ACCESS_DENIED). The refusal is DIAGNOSTIC of logon-SID-only granting: the \
                     network token DOES carry the user SID, so a user-SID ACE would have admitted it \
                     — PR #516's removal of that ACE is exactly what carries the boundary. This is a \
                     structural answer, stronger than the different-logon-SID form row (d) assumed.",
                )
            }
        }
    }

    pub fn main() -> i32 {
        let Ok(me) = current_user_sid() else {
            println!("P-17 UNRUN: cannot read this process's user SID.");
            return 2;
        };
        let Ok(my_logon) = current_logon_sid() else {
            println!("P-17 UNRUN: cannot read this process's logon SID.");
            return 2;
        };

        // `--serve` is the two-machine mode: a genuinely remote caller (a
        // second domain-joined box dialling `\\<this-host>\pipe\…` as the same
        // AD user over SSO) is the only thing that crosses a logon session on
        // this hardware — single-box transports reuse the token (§4.5) and a
        // second interactive session is not available on a client SKU (§4.6).
        // Without `--serve` the probe runs the single-box transport survey,
        // which is now expected to report UNRUN and stands as that evidence.
        if std::env::args().any(|a| a == "--serve") {
            return serve(&me, &my_logon);
        }

        // ---- (b) mechanism: find a transport that actually crosses a
        // logon-session boundary, or report that none on this box does. ----
        //
        // A same-session caller cannot attribute a refusal in (c)/(d) — the
        // refusal would be measuring a local open wearing a remote name. So
        // every host is probed for the caller's logon SID, and the first one
        // observed to DIFFER from ours is the transport the attribution rows
        // use. A host that reuses our token is reported and skipped, not
        // failed: it is correct behaviour (that caller genuinely is us), just
        // useless for this question.
        let mut crossing: Option<(String, CrossingForm)> = None;
        for (i, host) in transport_hosts().into_iter().enumerate() {
            match mechanism_row(&me, &host, SPAWN_MECH_BASE + i as u64) {
                // A different USER means the DACL never granted this caller at
                // all — a refusal would be over-determined, not the ACE's.
                Ok(SidTriage::Both { user, .. }) if user != me.as_str() => {
                    println!(
                        "P-17 mechanism: `\\\\{host}\\pipe\\` carries a DIFFERENT user SID — a \
                         refusal would be over-determined (not in the DACL at all), so this \
                         host cannot attribute the ACE. Recorded, skipped."
                    );
                }
                Ok(SidTriage::UserOkNoLogon { user }) if user != me.as_str() => {
                    println!(
                        "P-17 mechanism: `\\\\{host}\\pipe\\` carries a DIFFERENT user SID and no \
                         logon SID — over-determined, cannot attribute the ACE. Recorded, skipped."
                    );
                }
                // Same user, DIFFERENT logon SID — the terminal-services crossing.
                Ok(SidTriage::Both { logon, .. }) if logon != my_logon.as_str() => {
                    println!(
                        "P-17 mechanism: a caller via `\\\\{host}\\pipe\\` carries logon SID \
                         {logon} — distinct from ours ({}). This transport crosses a session \
                         boundary; the attribution rows use it.",
                        my_logon.as_str()
                    );
                    crossing = Some((host, CrossingForm::DifferentLogonSid));
                    break;
                }
                // Same user, NO logon SID — the network (`IPC$`) crossing. A
                // no-logon-SID token cannot match the ACE, so it crosses
                // structurally; serve() reaches the same conclusion (§4.8).
                Ok(SidTriage::UserOkNoLogon { .. }) => {
                    println!(
                        "P-17 mechanism: a caller via `\\\\{host}\\pipe\\` carries our user SID \
                         but NO logon SID — a network logon. It crosses the session boundary \
                         structurally (a no-logon-SID token cannot match the logon-SID ACE); \
                         the attribution rows use it."
                    );
                    crossing = Some((host, CrossingForm::NoLogonSid));
                    break;
                }
                // Same user, OUR logon SID — reuses the token, does not cross.
                Ok(SidTriage::Both { logon, .. }) => {
                    println!(
                        "P-17 mechanism: a caller via `\\\\{host}\\pipe\\` carries OUR logon SID \
                         ({logon}) — this transport reuses the caller's token and does not cross \
                         a session boundary. Recorded, skipped."
                    );
                }
                Ok(SidTriage::Unreadable(detail)) | Err(detail) => {
                    println!("P-17 mechanism: `\\\\{host}\\pipe\\` did not measure — {detail}");
                }
            }
        }
        let Some((host, crossing_form)) = crossing else {
            println!(
                "P-17 UNRUN: no single-box SMB transport crossed a logon-session boundary \
                 (localhost reuses the token by construction; the machine-name form did \
                 not cross either, or was unavailable). WP-D6's `IPC$` claim — the \
                 logon-SID ACE refusing a caller in a *different* session — therefore \
                 remains UNTESTED, and needs a genuinely remote caller via `--serve` and \
                 a second machine (§4.5–4.7). The `reject_remote_clients` fence, by \
                 contrast, IS testable single-box and has been (§4.7): it refuses a \
                 `\\\\HOST\\pipe\\` dial by path form. Not a pass, and NOT a falsification \
                 of WP-D6: this method could not reach the ACE question."
            );
            return 2;
        };

        // ---- (a) control: the production shape admits its own session. ----
        let Ok(descriptor) = OwnerOnlyDescriptor::new(&me, &my_logon) else {
            println!("P-17 UNRUN: could not build the production descriptor.");
            return 2;
        };
        let control_name = self_hosted_pipe_name(&me, SPAWN_CONTROL);
        let control = match create_instance(&control_name, descriptor.attributes_ptr(), true) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the control pipe (os error {e}).");
                return 2;
            }
        };
        let local = try_open(&control_name);
        drop(control);
        if local != 0 {
            println!(
                "P-17 UNRUN: the control open FAILED (os error {local}) — the production \
                 shape refused its own session locally, so nothing below would measure \
                 the transport. Not a pass."
            );
            return 2;
        }
        println!("P-17 control: the production pipe opens locally at Medium (as expected).");

        // ---- (c) production shape over the crossing transport. ----
        let prod_name = self_hosted_pipe_name(&me, SPAWN_PROD);
        let Some(prod_remote) = remote_form(&prod_name, &host) else {
            println!("P-17 UNRUN: pipe name did not carry the expected prefix.");
            return 2;
        };
        let prod = match create_instance(&prod_name, descriptor.attributes_ptr(), true) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the production-shape pipe (os error {e}).");
                return 2;
            }
        };
        let prod_result = try_open(&prod_remote);
        drop(prod);
        if prod_result == 0 {
            println!(
                "P-17 FAIL: the PRODUCTION-SHAPE pipe admitted a cross-session caller over \
                 `\\\\{host}\\pipe\\`. That is a live `IPC$` hole, not a documentation gap. \
                 Revisits WP-D6 — urgently."
            );
            return 1;
        }
        println!(
            "P-17 production: the cross-session open is refused (os error {prod_result}); \
             which of the three fences refused it is deliberately not claimed — that is \
             row (d)'s job."
        );

        // ---- (d) the D6 claim proper: DACL alone, every other fence down. --
        // `without_label_for_testing` keeps the same owner and the same
        // single-ACE DACL and drops the mandatory label; the remote-client
        // flag is off. If this refuses, only the logon-SID ACE can have done
        // it — the caller was admitted by an identical DACL-less-label shape
        // in (b)? No: (b) was permissive. What isolates the ACE is that every
        // OTHER mechanism this probe knows about is lowered, and (b) proved
        // the caller reaches pipes over this path when the DACL allows it.
        let Ok(dacl_only) = OwnerOnlyDescriptor::without_label_for_testing(&me, &my_logon) else {
            println!("P-17 UNRUN: could not build the DACL-only descriptor.");
            return 2;
        };
        let d_name = self_hosted_pipe_name(&me, SPAWN_DACL_ONLY);
        let Some(d_remote) = remote_form(&d_name, &host) else {
            println!("P-17 UNRUN: pipe name did not carry the expected prefix.");
            return 2;
        };
        let d_pipe = match create_instance(&d_name, dacl_only.attributes_ptr(), false) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the DACL-only pipe (os error {e}).");
                return 2;
            }
        };
        let d_result = try_open(&d_remote);
        drop(d_pipe);
        // Same verdict ladder serve() uses, so the two paths cannot drift — and
        // narrated for the crossing form actually observed, rather than always
        // in the different-logon-SID language. `prod_result` is known nonzero
        // here (row (c) returned above if it was 0), so the helper's
        // production-hole arm cannot fire; this reduces to the DACL-only ladder.
        let (on_admit, on_pass) = match crossing_form {
            CrossingForm::DifferentLogonSid => (
                "P-17 FAIL: with the remote-client flag and the label both down, a genuine \
                 cross-session (different-logon-SID) caller was ADMITTED. The logon-SID ACE does \
                 not carry the `IPC$` boundary on its own; PR #516's user-SID removal bought \
                 nothing on this axis. Revisits WP-D6",
                "P-17 PASS: with every other fence down, a genuine cross-session \
                 (different-logon-SID) caller is refused with ERROR_ACCESS_DENIED — the logon-SID \
                 ACE alone carries the `IPC$` boundary. WP-D6 is now an observation",
            ),
            CrossingForm::NoLogonSid => (
                "P-17 FAIL: with the remote-client flag and the label both down, a same-user \
                 caller whose token carries NO logon SID was ADMITTED — a token that cannot match \
                 the logon-SID ACE was let in anyway. WP-D6's boundary does not hold. Revisits \
                 WP-D6",
                "P-17 PASS (structural): with every other fence down, a same-user caller carrying \
                 NO logon SID (a network logon) cannot match the logon-SID-only ACE and is refused \
                 with ERROR_ACCESS_DENIED. The token DOES carry the user SID, so a user-SID ACE \
                 would have admitted it — the refusal is diagnostic of logon-SID-only granting. \
                 WP-D6's `IPC$` claim is now a structural observation",
            ),
        };
        attribute_dacl_refusal(d_result, prod_result, on_admit, on_pass)
    }

    /// Row (b) for one host: a permissive pipe, a client that dials
    /// `\\<host>\pipe\…`, and the caller's identity read off the impersonation
    /// token — returned as the SAME [`SidTriage`] `serve` produces, so a
    /// no-logon-SID network caller is recognised as a crossing on this path too,
    /// not swept into a generic "did not measure". `Ok(SidTriage)` is what was
    /// read; the crossing decision — different logon SID, no logon SID, or same
    /// session — is the caller's job. `Err` is a one-line reason the host did not
    /// measure (a transport-level failure), which `main` prints; it is always
    /// UNRUN, never a falsification. `spawn` names this attempt's pipe — callers
    /// pass a **distinct** value per host (see [`SPAWN_MECH_BASE`]) so a
    /// timed-out, detached client cannot cross into a later attempt's instance.
    fn mechanism_row(
        me: &shekyl_win_sec::SidString,
        host: &str,
        spawn: u64,
    ) -> Result<SidTriage, String> {
        let sd = SdFromSddl::new("D:(A;;GA;;;WD)")
            .map_err(|e| format!("could not build the permissive descriptor (os error {e})"))?;
        let mech_name = self_hosted_pipe_name(me, spawn);
        let Some(mech_remote) = remote_form(&mech_name, host) else {
            return Err("pipe name did not carry the expected prefix".to_owned());
        };
        let server = create_instance(&mech_name, sd.attributes_ptr(), false)
            .map_err(|e| format!("could not bind the mechanism pipe (os error {e})"))?;

        // The client: open over `\\<host>\pipe\`, write one byte
        // (impersonation requires the server to have read from the caller),
        // report the open result, then block on a read until the server
        // releases it. If the server bails early, dropping its guard closes
        // the instance and the blocked read fails — the thread cannot outlive
        // the row.
        let (tx, rx) = mpsc::channel::<u32>();
        let client = std::thread::spawn(move || {
            {
                let wide_name = wide(&mech_remote);
                // SAFETY: NUL-terminated, outlives the call.
                let handle = unsafe {
                    CreateFileW(
                        wide_name.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                        std::ptr::null_mut(),
                    )
                };
                if handle == INVALID_HANDLE_VALUE {
                    _ = tx.send(last_error());
                    return;
                }
                let guard = HandleGuard(handle);
                let payload = [0x17u8];
                let mut written: u32 = 0;
                // SAFETY: live handle, valid one-byte buffer.
                let wrote = unsafe {
                    WriteFile(
                        guard.0,
                        payload.as_ptr(),
                        1,
                        &raw mut written,
                        std::ptr::null_mut(),
                    )
                };
                if wrote == 0 || written != 1 {
                    _ = tx.send(last_error());
                    return;
                }
                _ = tx.send(0);
                // Hold the connection until the server releases it: the
                // impersonation token must describe a live caller, not a
                // hung-up one.
                let mut release = [0u8; 1];
                let mut read: u32 = 0;
                // SAFETY: live handle, valid buffer; a server-side close
                // fails this read rather than hanging it.
                unsafe {
                    ReadFile(
                        guard.0,
                        release.as_mut_ptr(),
                        1,
                        &raw mut read,
                        std::ptr::null_mut(),
                    )
                };
            }
        });

        // Everything that touches the server borrows it inside this closure;
        // the client thread is detached afterwards (see the drop below), never
        // joined, so a client wedged in a slow SMB connect cannot pull the wait
        // past CLIENT_TIMEOUT. Dropping the server closes its end, which fails
        // the client's blocking read and lets a connected thread exit on its own.
        let sid_result: Result<SidTriage, String> = (|| {
            let Ok(open_code) = rx.recv_timeout(CLIENT_TIMEOUT) else {
                return Err(format!(
                    "the client reported nothing within {}s — the SMB connect neither \
                     succeeded nor failed in bounded time",
                    CLIENT_TIMEOUT.as_secs()
                ));
            };
            if open_code != 0 {
                return Err(format!(
                    "the open of a PERMISSIVE pipe failed (os error {open_code}) — this \
                     transport is absent or refused even a wide-open pipe; on a box \
                     without a working `LanmanServer`/`IPC$` path this is expected"
                ));
            }

            // SAFETY: live server instance from create_instance above.
            let connected = unsafe { ConnectNamedPipe(server.0, std::ptr::null_mut()) };
            if connected == 0 && last_error() != ERROR_PIPE_CONNECTED {
                return Err(format!(
                    "ConnectNamedPipe failed (os error {})",
                    last_error()
                ));
            }
            let mut byte = [0u8; 1];
            let mut got: u32 = 0;
            // SAFETY: live handle, valid buffer.
            let read_ok = unsafe {
                ReadFile(
                    server.0,
                    byte.as_mut_ptr(),
                    1,
                    &raw mut got,
                    std::ptr::null_mut(),
                )
            };
            if read_ok == 0 || got != 1 {
                return Err(format!(
                    "could not read the caller's byte (os error {})",
                    last_error()
                ));
            }

            // SAFETY: the caller has written and we have read (the documented
            // precondition). The impersonation is reverted on every path out
            // of this block, and a failed revert ABORTS — continuing to run
            // with a caller's identity on this thread is not a state this
            // probe may be in.
            let imp = unsafe { ImpersonateNamedPipeClient(server.0) };
            if imp == 0 {
                return Err(format!(
                    "ImpersonateNamedPipeClient failed (os error {})",
                    last_error()
                ));
            }
            let mut token: HANDLE = std::ptr::null_mut();
            // SAFETY: current-thread pseudo-handle; OpenAsSelf=1 so the query
            // is made with the PROCESS identity — the documented trap for a
            // caller that cannot open its own token.
            let opened =
                unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
            let token_guard = HandleGuard(token);
            let sids: Result<SidTriage, String> = if opened == 0 {
                Err(format!(
                    "could not open the impersonation token (os error {})",
                    last_error()
                ))
            } else {
                // Read BOTH SIDs and build the same `SidTriage` serve() does, so
                // `UserOkNoLogon` (a network caller with no logon SID) is a
                // first-class crossing here too, and `NoLogonSid` is not swept in
                // with a `QueryToken`/`Stringify` failure — that would be a false
                // structural claim. `{:?}` on the variant, never Display (its
                // TokenGroups text still names "user SID").
                Ok(
                    match (
                        user_sid_of_token_for_testing(token_guard.0),
                        logon_sid_of_token_for_testing(token_guard.0),
                    ) {
                        (Ok(u), Ok(l)) => SidTriage::Both {
                            user: u.as_str().to_owned(),
                            logon: l.as_str().to_owned(),
                        },
                        (Ok(u), Err(SidError::NoLogonSid)) => SidTriage::UserOkNoLogon {
                            user: u.as_str().to_owned(),
                        },
                        (Err(ue), _) => SidTriage::Unreadable(format!(
                            "could not read the caller's USER SID: {ue:?}"
                        )),
                        (Ok(_), Err(le)) => SidTriage::Unreadable(format!(
                            "could not read the caller's LOGON SID: {le:?}"
                        )),
                    },
                )
            };
            // SAFETY: paired with the successful impersonation above.
            let reverted = unsafe { RevertToSelf() };
            if reverted == 0 {
                eprintln!("P-17: RevertToSelf FAILED — aborting rather than run impersonated.");
                std::process::abort();
            }
            sids
        })();

        drop(server); // closes the server end, failing the client's blocked read
                      // Detach rather than join. On the normal paths dropping the server
                      // unblocks the client's release-read and it exits at once — but if the
                      // client is still stuck in a slow `CreateFileW` SMB connect (an
                      // unreachable name, a dropped SYN), `join()` would wait out that whole
                      // connect and defeat CLIENT_TIMEOUT, the bound this function advertises.
                      // A probe about to exit needs no reap; the thread dies at process exit,
                      // exactly as serve()'s accept thread is left to.
        drop(client);
        sid_result
    }
}
