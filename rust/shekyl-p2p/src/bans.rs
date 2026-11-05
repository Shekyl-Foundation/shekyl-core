// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ban verbs over the node's socket table, and the ban list's one
//! expiry owner.
//!
//! A ban is admission's: it refuses the next accept and the next dial
//! (`DRS_X_STORE_FLIP.md` DX-Q3, Q11). The sessions a new ban drops are the
//! session layer's to end, so while the network is up the verbs go through
//! the layer, which closes them; before it is up, and after it stops, they
//! go to the table alone, where there is nothing open to close. The RPC's
//! ban handle and the ban files both ban through here, so a ban has one
//! path.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_p2p_session::SessionLayer;
use shekyl_timing_engine::{Clock, Handle, MonotonicClock, OwnerClass, Tick};
use shekyl_transport_layer::{deadline_after, BanLeft, Ipv4Subnet, ListedBan, Sockets};

/// What a ban names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanTarget {
    /// One host.
    Host(IpAddr),
    /// An IPv4 subnet.
    Subnet(Ipv4Subnet),
}

/// How long a ban lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanSpan {
    /// Until it is lifted.
    Permanent,
    /// For this long from the process clock.
    For(Duration),
}

type Layer = SessionLayer<MonotonicClock>;

/// The ban verbs over one socket table on one clock.
#[derive(Clone)]
pub struct Bans {
    sockets: Sockets,
    clock: MonotonicClock,
    layer: Arc<Mutex<Option<Layer>>>,
}

impl Bans {
    /// The verbs over `sockets`, reading `clock`.
    #[must_use]
    pub fn new(sockets: Sockets, clock: MonotonicClock) -> Self {
        Self {
            sockets,
            clock,
            layer: Arc::new(Mutex::new(None)),
        }
    }

    /// The network is up: a ban now ends the sessions it drops.
    pub(crate) fn attach(&self, layer: Layer) {
        *self.layer.lock().expect("ban layer") = Some(layer);
    }

    /// The network stopped: the verbs go to the table alone.
    pub(crate) fn detach(&self) {
        *self.layer.lock().expect("ban layer") = None;
    }

    fn layer(&self) -> Option<Layer> {
        self.layer.lock().expect("ban layer").clone()
    }

    fn now(&self) -> Tick {
        self.clock.now()
    }

    /// Whether `span`'s deadline fits the clock now: what [`Self::ban`]
    /// would refuse, asked before any ban is made.
    #[must_use]
    pub fn fits(&self, span: BanSpan) -> bool {
        match span {
            BanSpan::Permanent => true,
            BanSpan::For(left) => deadline_after(self.now(), nanos_of(left)).is_some(),
        }
    }

    /// Ban `target` for `span`. `false` when the span's deadline does not
    /// fit the clock; nothing is banned then. A deadline already covered
    /// by a later one does not shorten it.
    pub fn ban(&self, target: BanTarget, span: BanSpan) -> bool {
        let now = self.now();
        let until = match span {
            BanSpan::Permanent => None,
            BanSpan::For(left) => {
                let Some(until) = deadline_after(now, nanos_of(left)) else {
                    return false;
                };
                Some(until)
            }
        };
        let _closed = match (target, until, self.layer()) {
            (BanTarget::Host(host), Some(until), Some(layer)) => layer.ban_host(host, until),
            (BanTarget::Host(host), None, Some(layer)) => layer.ban_host_permanent(host),
            (BanTarget::Subnet(subnet), Some(until), Some(layer)) => {
                layer.ban_subnet(subnet, until)
            }
            (BanTarget::Subnet(subnet), None, Some(layer)) => layer.ban_subnet_permanent(subnet),
            (BanTarget::Host(host), Some(until), None) => self.sockets.ban_host(host, until, now),
            (BanTarget::Host(host), None, None) => self.sockets.ban_host_permanent(host),
            (BanTarget::Subnet(subnet), Some(until), None) => {
                self.sockets.ban_subnet(subnet, until, now)
            }
            (BanTarget::Subnet(subnet), None, None) => self.sockets.ban_subnet_permanent(subnet),
        };
        true
    }

    /// Lift `target`'s ban. `false` when there was none. Open sockets stay
    /// open.
    pub fn lift(&self, target: BanTarget) -> bool {
        match target {
            BanTarget::Host(host) => self.sockets.lift_host(host),
            BanTarget::Subnet(subnet) => self.sockets.lift_subnet(subnet),
        }
    }

    /// Time left on the longest ban that covers `host`; `None` when it is
    /// not banned.
    #[must_use]
    pub fn remaining(&self, host: IpAddr) -> Option<BanLeft> {
        self.sockets.remaining(host, self.now())
    }

    /// Whether `host` is banned now.
    #[must_use]
    pub fn is_banned(&self, host: IpAddr) -> bool {
        self.sockets.is_banned(host)
    }

    /// The bans in force, with their time left.
    #[must_use]
    pub fn listed(&self) -> Vec<ListedBan> {
        self.sockets.listed(self.now())
    }
}

fn nanos_of(left: Duration) -> u64 {
    u64::try_from(left.as_nanos()).unwrap_or(u64::MAX)
}

/// Start the ban list's timing owner (Rick, 2026-10-31): one owner on the
/// process engine holds the earliest ban deadline; when it fires, every
/// ban due ends and the next deadline is armed. It is the only expiry: a
/// lookup never ends a ban. The table tells it of each deadline a new ban
/// makes the earliest ([`Sockets::set_ban_expiry`]), holding it only
/// weakly, so the task owns the registration. A task on `runtime`, not a
/// thread of its own (decision B, Rick 2026-10-25). It ends when the engine
/// closes or the runtime stops.
///
/// `generation` names the engine: the table hands out its timer once per
/// engine, so a second start against the same engine arms nothing twice.
pub(crate) fn spawn_expiry(
    runtime: &tokio::runtime::Handle,
    engine: &Handle<MonotonicClock>,
    sockets: Sockets,
    generation: u64,
) {
    let Some(timer) = sockets.take_ban_timer(generation) else {
        return;
    };
    let owner = match engine.register(OwnerClass::Housekeeping) {
        Ok(owner) => Arc::new(owner),
        Err(err) => {
            tracing::error!(
                "the ban list's timer could not start ({err:?}): a timed ban stays in force \
                 until it is lifted"
            );
            drop(timer);
            return;
        }
    };
    let arming = Arc::downgrade(&owner);
    sockets.set_ban_expiry(Arc::new(move |deadline| {
        if let Some(owner) = arming.upgrade() {
            if let Err(err) = owner.arm(deadline) {
                tracing::debug!("the ban list's timer is not running ({err:?})");
            }
        }
    }));
    drop(runtime.spawn(async move {
        let _timer = timer;
        while owner.wait_wake_async().await.is_ok() {
            if let Some(next) = sockets.expire_bans(owner.clock().now()) {
                if owner.arm(next).is_err() {
                    return;
                }
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn bans() -> Bans {
        Bans::new(Sockets::new(), MonotonicClock::new())
    }

    #[test]
    fn a_permanent_ban_is_listed_until_lifted() {
        let bans = bans();
        let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        assert!(!bans.is_banned(host));
        assert!(bans.ban(BanTarget::Host(host), BanSpan::Permanent));
        assert!(bans.is_banned(host));
        assert_eq!(bans.listed().len(), 1);
        assert!(bans.lift(BanTarget::Host(host)));
        assert!(!bans.is_banned(host));
        assert!(!bans.lift(BanTarget::Host(host)));
    }

    #[test]
    fn a_span_past_the_clock_is_refused_before_anything_is_banned() {
        let bans = bans();
        let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        let span = BanSpan::For(Duration::from_nanos(u64::MAX));
        assert!(!bans.fits(span));
        assert!(!bans.ban(BanTarget::Host(host), span));
        assert!(!bans.is_banned(host));
    }

    /// The expiry owner is the only thing that ends a timed ban: past its
    /// deadline the ban holds until the owner runs, then the owner ends it.
    #[test]
    fn the_expiry_owner_ends_a_timed_ban_and_nothing_else_does() {
        let sockets = Sockets::new();
        let clock = MonotonicClock::new();
        let bans = Bans::new(sockets.clone(), clock.clone());
        let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
        assert!(bans.ban(
            BanTarget::Host(host),
            BanSpan::For(Duration::from_millis(1))
        ));
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            bans.is_banned(host),
            "past its deadline, and no owner has run"
        );

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .expect("runtime");
        let engine = shekyl_timing_engine::EngineService::start(clock);
        spawn_expiry(runtime.handle(), &engine.handle(), sockets, 1);
        let give_up = std::time::Instant::now() + Duration::from_secs(10);
        while bans.is_banned(host) {
            assert!(
                std::time::Instant::now() < give_up,
                "the expiry owner never ended the ban"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(engine);
        drop(runtime);
    }

    #[test]
    fn a_timed_ban_reports_what_is_left() {
        let bans = bans();
        let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert!(bans.ban(
            BanTarget::Host(host),
            BanSpan::For(Duration::from_secs(3600))
        ));
        assert!(bans.remaining(host).is_some());
    }
}
