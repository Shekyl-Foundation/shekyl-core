// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::*;
use crate::{ManualClock, OwnerClass, Tick};

#[test]
fn a_later_arm_is_not_sent_until_the_wake_resets_the_handle() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service
        .handle()
        .register(OwnerClass::Transport)
        .expect("register");
    owner.arm(Tick::new(100)).unwrap();
    service.barrier();
    assert_eq!(service.arms_applied(), 1);
    owner.arm(Tick::new(250)).unwrap();
    service.barrier();
    assert_eq!(service.arms_applied(), 1, "a later arm entered the mailbox");
    service.advance(Tick::new(100));
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("first wake");
    assert_eq!(wake.deadline, Tick::new(100));
    owner.arm(Tick::new(400)).unwrap();
    service.barrier();
    assert_eq!(
        service.arms_applied(),
        2,
        "taking the wake did not reset the handle"
    );
    service.advance(Tick::new(400));
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("re-armed wake");
    assert_eq!(wake.deadline, Tick::new(400));
    assert!(owner.poll_wake().unwrap().is_none());
}

#[test]
fn clear_resets_the_handle_so_a_later_arm_is_sent() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service
        .handle()
        .register(OwnerClass::Transport)
        .expect("register");
    owner.arm(Tick::new(100)).unwrap();
    service.barrier();
    owner.clear().unwrap();
    owner.arm(Tick::new(300)).unwrap();
    service.barrier();
    assert_eq!(service.arms_applied(), 2);
    service.advance(Tick::new(300));
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("arm after clear");
    assert_eq!(wake.deadline, Tick::new(300));
}

/// `clear` then a later arm, while the fired wake is still in the slot.
/// Taking that wake must not forget the arm `clear` allowed, or the next
/// later arm is sent and the engine keeps the sooner deadline.
#[test]
fn a_waiting_wake_does_not_forget_the_arm_clear_allowed() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service
        .handle()
        .register(OwnerClass::Transport)
        .expect("register");
    owner.arm(Tick::new(10)).unwrap();
    service.barrier();
    service.advance(Tick::new(10));
    service.barrier();
    owner.clear().unwrap();
    owner.arm(Tick::new(50)).unwrap();
    service.barrier();
    let stale = owner.poll_wake().unwrap().expect("waiting wake");
    assert_eq!(stale.deadline, Tick::new(10));
    owner.arm(Tick::new(80)).unwrap();
    service.barrier();
    assert_eq!(
        service.arms_applied(),
        2,
        "a later arm was sent while 50 was still armed"
    );
    service.advance(Tick::new(50));
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("the arm clear allowed");
    assert_eq!(wake.deadline, Tick::new(50));
    owner.arm(Tick::new(80)).unwrap();
    service.barrier();
    assert_eq!(service.arms_applied(), 3);
    service.advance(Tick::new(80));
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("arm after the new wake");
    assert_eq!(wake.deadline, Tick::new(80));
}

/// The same tick, re-armed after clear, is a new arm. Deadline equality
/// cannot tell it from the wake that is still waiting.
#[test]
fn a_waiting_wake_does_not_forget_a_same_tick_rearm() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service
        .handle()
        .register(OwnerClass::Transport)
        .expect("register");
    owner.arm(Tick::new(10)).unwrap();
    service.barrier();
    service.advance(Tick::new(10));
    service.barrier();
    owner.clear().unwrap();
    owner.arm(Tick::new(10)).unwrap();
    let stale = owner.poll_wake().unwrap().expect("waiting wake");
    assert_eq!(stale.deadline, Tick::new(10));
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("re-arm");
    assert_eq!(wake.deadline, Tick::new(10));
    owner.arm(Tick::new(30)).unwrap();
    service.barrier();
    assert_eq!(service.arms_applied(), 3);
    service.advance(Tick::new(30));
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("later arm");
    assert_eq!(wake.deadline, Tick::new(30));
}

#[test]
fn every_handle_refuses_once_the_service_is_closed() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let first = service.handle();
    let second = first.clone();
    let owner = first.register(OwnerClass::Relay).unwrap();
    service.barrier();
    service.close();
    assert!(matches!(
        first.register(OwnerClass::Relay),
        Err(EngineError::Closed)
    ));
    assert!(matches!(
        second.register(OwnerClass::Transport),
        Err(EngineError::Closed)
    ));
    assert!(matches!(owner.arm(Tick::new(1)), Err(EngineError::Closed)));
    assert!(matches!(owner.clear(), Err(EngineError::Closed)));
    assert!(matches!(owner.deregister(), Err(EngineError::Closed)));
}

#[test]
fn a_command_queued_before_close_is_not_applied() {
    let service = EngineService::start_paused(ManualClock::new(Tick::new(1_000)));
    let owner = service
        .handle()
        .register(OwnerClass::Transport)
        .expect("queued register");
    owner
        .arm(Tick::new(1))
        .expect("queued arm of an already-due deadline");
    service.close();
    service.release();
    service.wait_stopped();
    assert_eq!(service.registers_applied(), 0);
    assert_eq!(service.arms_applied(), 0);
    assert!(matches!(owner.poll_wake(), Err(EngineError::Closed)));
}

#[test]
fn concurrent_homes_fire_each_live_deadline_once() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let (tx, rx) = mpsc::channel();
    thread::scope(|scope| {
        for index in 0..32u64 {
            let handle = service.handle();
            let tx = tx.clone();
            scope.spawn(move || {
                let owner = handle.register(OwnerClass::Transport).unwrap();
                let base = 10_000 + index * 100;
                owner.arm(Tick::new(base)).unwrap();
                owner.arm(Tick::new(base + 50)).unwrap();
                let expect = match index % 4 {
                    0 => {
                        owner.clear().unwrap();
                        None
                    }
                    1 => {
                        owner.deregister().unwrap();
                        None
                    }
                    2 => {
                        let earlier = base - 10;
                        owner.arm(Tick::new(earlier)).unwrap();
                        Some(earlier)
                    }
                    _ => Some(base),
                };
                tx.send((owner, expect)).unwrap();
            });
        }
    });
    drop(tx);
    let owners: Vec<_> = rx.into_iter().collect();
    assert_eq!(owners.len(), 32);
    service.barrier();
    service.advance(Tick::new(100_000));
    service.barrier();
    let mut rearm = None;
    for (owner, expect) in owners {
        match expect {
            None => match owner.poll_wake() {
                Ok(None) | Err(EngineError::UnknownOwner | EngineError::Closed) => {}
                Ok(Some(wake)) => panic!("cleared or deregistered owner fired: {wake:?}"),
                Err(err) => panic!("unexpected {err:?}"),
            },
            Some(deadline) => {
                let wake = owner.poll_wake().unwrap().expect("live deadline");
                assert_eq!(wake.deadline.get(), deadline);
                assert!(owner.poll_wake().unwrap().is_none());
                if rearm.is_none() {
                    rearm = Some((owner, deadline + 10_000));
                }
            }
        }
    }
    let (owner, later) = rearm.expect("one live owner");
    owner.arm(Tick::new(later)).unwrap();
    service.barrier();
    service.advance(Tick::new(later));
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("re-arm after wake");
    assert_eq!(wake.deadline.get(), later);
    assert!(owner.poll_wake().unwrap().is_none());
}

#[test]
fn engine_thread_panic_aborts_the_process() {
    if std::env::var_os("SHEKYL_TIMING_ENGINE_ABORT_CHILD").is_some() {
        let service = EngineService::start(ManualClock::new(Tick::new(0)));
        service.fail_the_thread();
        thread::sleep(Duration::from_secs(2));
        eprintln!("engine thread panic did not abort the process");
        std::process::exit(17);
    }
    let name = thread::current()
        .name()
        .expect("the test harness names this thread")
        .to_string();
    let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .arg("--exact")
        .arg(&name)
        .env("SHEKYL_TIMING_ENGINE_ABORT_CHILD", "1")
        .status()
        .expect("spawn the abort child");
    #[cfg(unix)]
    assert_eq!(
        status.signal(),
        Some(6),
        "expected SIGABRT from process::abort, got {status:?}"
    );
    #[cfg(not(unix))]
    assert!(
        !status.success(),
        "expected the child process to abort, got {status:?}"
    );
}

#[test]
fn a_deadline_that_has_not_fired_is_dropped_at_close() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service.handle().register(OwnerClass::Transport).unwrap();
    owner.arm(Tick::new(100)).unwrap();
    service.barrier();
    service.close();
    assert!(matches!(owner.poll_wake(), Err(EngineError::Closed)));
    assert!(matches!(owner.poll_wake(), Err(EngineError::Closed)));
}

#[test]
fn after_close_returns_a_poll_stays_closed() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service.handle().register(OwnerClass::Transport).unwrap();
    owner.arm(Tick::new(50)).unwrap();
    service.barrier();
    service.advance(Tick::new(50));
    service.close();
    let first = owner.poll_wake();
    let second = owner.poll_wake();
    match first {
        Ok(Some(wake)) => {
            assert_eq!(wake.deadline, Tick::new(50));
            assert!(matches!(second, Err(EngineError::Closed)));
        }
        Err(EngineError::Closed) => {
            assert!(matches!(second, Err(EngineError::Closed)));
        }
        other => panic!("close returned and then the slot changed: {other:?}"),
    }
}

#[test]
fn a_wait_on_a_registration_closed_before_it_is_applied_returns_closed() {
    let service = EngineService::start_paused(ManualClock::new(Tick::new(0)));
    let owner = service.handle().register(OwnerClass::Transport).unwrap();
    let slot = Arc::clone(&owner.slot);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        tx.send(owner.wait_wake()).expect("test thread alive");
    });
    while !slot.is_parked() {
        thread::yield_now();
    }
    service.close();
    service.release();
    service.wait_stopped();
    let result = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("wait_wake blocked after close dropped the registration");
    assert!(matches!(result, Err(EngineError::Closed)));
}

/// Two waits on an owner whose slot already holds a wake. The first
/// returns that wake. The second returns the terminal error.
fn both_waits(
    owner: OwnerHandle<ManualClock>,
) -> (Result<Wake, EngineError>, Result<Wake, EngineError>) {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let first = owner.wait_wake();
        let second = owner.wait_wake();
        tx.send((first, second)).expect("test thread alive");
    });
    rx.recv_timeout(Duration::from_secs(2))
        .expect("wait_wake blocked after the owner was finished")
}

#[test]
fn a_wake_pending_at_close_is_handed_out_once() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service.handle().register(OwnerClass::Transport).unwrap();
    owner.arm(Tick::new(1)).unwrap();
    service.barrier();
    service.advance(Tick::new(1));
    service.barrier();
    service.close();
    service.wait_stopped();
    let (first, second) = both_waits(owner);
    assert_eq!(first.expect("the pending wake").deadline, Tick::new(1));
    assert!(matches!(second, Err(EngineError::Closed)));
}

#[test]
fn a_wake_pending_at_deregister_is_handed_out_once() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service.handle().register(OwnerClass::Transport).unwrap();
    owner.arm(Tick::new(1)).unwrap();
    service.barrier();
    service.advance(Tick::new(1));
    service.barrier();
    owner.deregister().unwrap();
    service.barrier();
    let (first, second) = both_waits(owner);
    assert_eq!(first.expect("the pending wake").deadline, Tick::new(1));
    assert!(matches!(second, Err(EngineError::UnknownOwner)));
}

#[test]
fn a_deregistered_handle_does_not_poll_an_empty_slot_as_idle() {
    let service = EngineService::start_paused(ManualClock::new(Tick::new(0)));
    let owner = service.handle().register(OwnerClass::Relay).unwrap();
    owner.deregister().unwrap();
    assert!(matches!(owner.poll_wake(), Err(EngineError::UnknownOwner)));
    service.close();
    service.release();
    service.wait_stopped();
}

#[test]
fn taking_a_wake_records_the_home_delay() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service.handle().register(OwnerClass::Transport).unwrap();
    owner.arm(Tick::new(10)).unwrap();
    service.barrier();
    service.advance(Tick::new(10));
    service.barrier();
    service.advance(Tick::new(25));
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("wake");
    assert_eq!(wake.fired_at, Tick::new(10));
    let totals = service.lateness(OwnerClass::Transport);
    assert_eq!(totals.fires, 1);
    assert_eq!(totals.home_reports, 1);
    assert_eq!(totals.home_delay, 15);
}

#[test]
fn an_arm_then_a_clear_run_in_that_order() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service.handle().register(OwnerClass::Transport).unwrap();
    owner.arm(Tick::new(100)).unwrap();
    owner.clear().unwrap();
    service.barrier();
    assert_eq!(service.arms_applied(), 1);
    service.advance(Tick::new(100));
    service.barrier();
    assert!(matches!(owner.poll_wake(), Ok(None)));
}

#[test]
fn a_second_wake_replaces_the_one_still_in_the_slot() {
    let service = EngineService::start(ManualClock::new(Tick::new(0)));
    let owner = service.handle().register(OwnerClass::Transport).unwrap();
    owner.arm(Tick::new(10)).unwrap();
    service.barrier();
    service.advance(Tick::new(10));
    service.barrier();
    owner.arm(Tick::new(4)).unwrap();
    service.barrier();
    let wake = owner.poll_wake().unwrap().expect("the replacement");
    assert_eq!(wake.deadline, Tick::new(4));
    assert!(matches!(owner.poll_wake(), Ok(None)));
    assert_eq!(service.lateness(OwnerClass::Transport).replaced_wakes, 1);
}
