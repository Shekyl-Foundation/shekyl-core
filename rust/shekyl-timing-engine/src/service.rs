// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The engine service from `P2P_TIMING_ENGINE.md`'s addendum.
//!
//! One std thread owns the [`Engine`](crate::Engine). Homes send on a
//! mailbox and do not wait for the engine to apply the command. The
//! handle drops an arm that is not strictly earlier, so that command
//! never enters the mailbox. That memory resets when the home takes a
//! wake, and on clear and deregister.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::{Clock, Engine, EngineError, Generation, IdSource, OwnerClass, OwnerId, Tick, Wake};

enum Command {
    Register {
        id: OwnerId,
        class: OwnerClass,
        slot: Arc<Slot>,
    },
    Arm {
        id: OwnerId,
        deadline: Tick,
    },
    Clear {
        id: OwnerId,
    },
    Deregister {
        id: OwnerId,
    },
    NoteHome {
        id: OwnerId,
        generation: Generation,
        polled_at: Tick,
    },
    Shutdown,
    #[cfg(test)]
    Advance(Tick),
    #[cfg(test)]
    Barrier(Sender<()>),
    #[cfg(test)]
    Panic,
}

enum SlotState {
    Empty,
    Wake(Wake),
    Closed,
    Gone,
}

struct Slot {
    state: Mutex<SlotState>,
    cvar: Condvar,
}

impl Slot {
    fn new() -> Self {
        Self {
            state: Mutex::new(SlotState::Empty),
            cvar: Condvar::new(),
        }
    }

    fn deliver(&self, wake: Wake) {
        let mut state = self.state.lock().expect("slot lock");
        if matches!(*state, SlotState::Closed | SlotState::Gone) {
            return;
        }
        let notify = matches!(*state, SlotState::Empty);
        *state = SlotState::Wake(wake);
        if notify {
            self.cvar.notify_one();
        }
    }

    fn poll(&self) -> Result<Option<Wake>, EngineError> {
        let mut state = self.state.lock().expect("slot lock");
        match std::mem::replace(&mut *state, SlotState::Empty) {
            SlotState::Wake(wake) => Ok(Some(wake)),
            SlotState::Closed => {
                *state = SlotState::Closed;
                Err(EngineError::Closed)
            }
            SlotState::Gone => {
                *state = SlotState::Gone;
                Err(EngineError::UnknownOwner)
            }
            SlotState::Empty => Ok(None),
        }
    }

    fn wait(&self) -> Result<Wake, EngineError> {
        let mut state = self.state.lock().expect("slot lock");
        loop {
            match std::mem::replace(&mut *state, SlotState::Empty) {
                SlotState::Wake(wake) => return Ok(wake),
                SlotState::Closed => {
                    *state = SlotState::Closed;
                    return Err(EngineError::Closed);
                }
                SlotState::Gone => {
                    *state = SlotState::Gone;
                    return Err(EngineError::UnknownOwner);
                }
                SlotState::Empty => {
                    state = self.cvar.wait(state).expect("slot lock");
                }
            }
        }
    }

    fn seal(&self, next: SlotState) {
        let mut state = self.state.lock().expect("slot lock");
        if matches!(*state, SlotState::Empty) {
            *state = next;
            self.cvar.notify_all();
        }
    }
}

#[cfg(test)]
struct Gate {
    held: Mutex<bool>,
    cvar: Condvar,
}

#[cfg(test)]
impl Gate {
    fn new(held: bool) -> Self {
        Self {
            held: Mutex::new(held),
            cvar: Condvar::new(),
        }
    }

    fn wait(&self) {
        let mut held = self.held.lock().expect("gate lock");
        while *held {
            held = self.cvar.wait(held).expect("gate lock");
        }
    }

    fn release(&self) {
        *self.held.lock().expect("gate lock") = false;
        self.cvar.notify_all();
    }
}

#[cfg(test)]
struct Counts {
    registers: AtomicUsize,
    arms: AtomicUsize,
}

enum Park {
    Due,
    Timeout(Duration),
    Block,
}

fn park<C: Clock>(engine: &mut Engine<C>) -> Park {
    let Some(deadline) = engine.next_deadline() else {
        return Park::Block;
    };
    match engine.clock().wait_for(deadline) {
        Some(wait) if wait.is_zero() => Park::Due,
        Some(wait) => Park::Timeout(wait),
        None => Park::Block,
    }
}

/// One thread, one mailbox, the closed flag every handle shares.
pub struct EngineService<C: Clock> {
    tx: Sender<Command>,
    closed: Arc<AtomicBool>,
    ids: IdSource,
    clock: C,
    thread: Mutex<Option<JoinHandle<()>>>,
    #[cfg(test)]
    gate: Arc<Gate>,
    #[cfg(test)]
    counts: Arc<Counts>,
}

impl<C: Clock + Clone + Send + 'static> EngineService<C> {
    /// Start the engine thread. A panic on that thread aborts the process.
    ///
    /// The workspace builds `dev` and `release` with `panic = "abort"`, so
    /// the runtime aborts before this thread can catch anything. `cargo test`
    /// builds the harness with `panic = "unwind"`. The catch below is what
    /// makes that configuration abort too, instead of leaving the thread
    /// dead and every deadline unarmed.
    pub fn start(clock: C) -> Self {
        Self::spawn(clock, Arc::new(|| std::process::abort()))
    }

    fn spawn(clock: C, terminal: Arc<dyn Fn() + Send + Sync>) -> Self {
        let (tx, rx) = mpsc::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let ids = IdSource::new();
        let engine_clock = clock.clone();
        #[cfg(test)]
        let gate = Arc::new(Gate::new(false));
        #[cfg(test)]
        let counts = Arc::new(Counts {
            registers: AtomicUsize::new(0),
            arms: AtomicUsize::new(0),
        });
        let thread_closed = Arc::clone(&closed);
        #[cfg(test)]
        let thread_gate = Arc::clone(&gate);
        #[cfg(test)]
        let thread_counts = Arc::clone(&counts);
        let thread = thread::Builder::new()
            .name("shekyl-timing".to_string())
            .spawn(move || {
                let engine = Engine::new(engine_clock);
                let finished = catch_unwind(AssertUnwindSafe(|| {
                    worker(
                        engine,
                        &rx,
                        &thread_closed,
                        #[cfg(test)]
                        &thread_gate,
                        #[cfg(test)]
                        &thread_counts,
                    );
                }));
                if finished.is_err() {
                    terminal();
                }
            })
            .expect("timing engine thread");
        Self {
            tx,
            closed,
            ids,
            clock,
            thread: Mutex::new(Some(thread)),
            #[cfg(test)]
            gate,
            #[cfg(test)]
            counts,
        }
    }

    /// A handle. Every handle from this service shares the closed flag
    /// and the id counter.
    pub fn handle(&self) -> Handle<C> {
        Handle {
            tx: self.tx.clone(),
            closed: Arc::clone(&self.closed),
            ids: self.ids.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Shutdown step 1. Later `register`, `arm`, `clear`, and `deregister`
    /// return [`EngineError::Closed`] and send nothing. A command already
    /// in the mailbox is dropped, not applied.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        drop(self.tx.send(Command::Shutdown));
    }
}

impl<C: Clock> Drop for EngineService<C> {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        #[cfg(test)]
        self.gate.release();
        drop(self.tx.send(Command::Shutdown));
        if let Some(thread) = self.thread.lock().expect("thread lock").take() {
            drop(thread.join());
        }
    }
}

fn worker<C: Clock>(
    mut engine: Engine<C>,
    rx: &Receiver<Command>,
    closed: &AtomicBool,
    #[cfg(test)] gate: &Gate,
    #[cfg(test)] counts: &Counts,
) {
    let mut deliveries: HashMap<OwnerId, Arc<Slot>> = HashMap::new();
    loop {
        #[cfg(test)]
        gate.wait();
        if !step(
            &mut engine,
            rx,
            closed,
            &mut deliveries,
            #[cfg(test)]
            counts,
        ) {
            break;
        }
    }
    for slot in deliveries.values() {
        slot.seal(SlotState::Closed);
    }
    engine.close();
}

fn step<C: Clock>(
    engine: &mut Engine<C>,
    rx: &Receiver<Command>,
    closed: &AtomicBool,
    deliveries: &mut HashMap<OwnerId, Arc<Slot>>,
    #[cfg(test)] counts: &Counts,
) -> bool {
    let incoming = match park(engine) {
        Park::Due => match rx.try_recv() {
            Ok(command) => command,
            Err(TryRecvError::Empty) => {
                deliver_due(engine, deliveries);
                return true;
            }
            Err(TryRecvError::Disconnected) => return false,
        },
        Park::Timeout(wait) => match rx.recv_timeout(wait) {
            Ok(command) => command,
            Err(RecvTimeoutError::Timeout) => {
                deliver_due(engine, deliveries);
                return true;
            }
            Err(RecvTimeoutError::Disconnected) => return false,
        },
        Park::Block => match rx.recv() {
            Ok(command) => command,
            Err(_) => return false,
        },
    };
    dispatch(
        engine,
        rx,
        closed,
        deliveries,
        incoming,
        #[cfg(test)]
        counts,
    )
}

fn dispatch<C: Clock>(
    engine: &mut Engine<C>,
    rx: &Receiver<Command>,
    closed: &AtomicBool,
    deliveries: &mut HashMap<OwnerId, Arc<Slot>>,
    command: Command,
    #[cfg(test)] counts: &Counts,
) -> bool {
    match command {
        Command::Shutdown => {
            while rx.try_recv().is_ok() {}
            return false;
        }
        #[cfg(test)]
        Command::Panic => panic!("timing engine thread failed"),
        #[cfg(test)]
        Command::Barrier(reply) => {
            deliver_due(engine, deliveries);
            ignore(reply.send(()));
            return true;
        }
        other if closed.load(Ordering::Acquire) => {
            drop(other);
            return true;
        }
        Command::Register { id, class, slot } => {
            if engine.register(id, class).is_ok() {
                deliveries.insert(id, slot);
                #[cfg(test)]
                counts.registers.fetch_add(1, Ordering::Relaxed);
            }
        }
        Command::Arm { id, deadline } => {
            if engine.arm(id, deadline).is_ok() {
                #[cfg(test)]
                counts.arms.fetch_add(1, Ordering::Relaxed);
            }
        }
        Command::Clear { id } => {
            ignore(engine.clear(id));
        }
        Command::Deregister { id } => {
            ignore(engine.deregister(id));
            if let Some(slot) = deliveries.remove(&id) {
                slot.seal(SlotState::Gone);
            }
        }
        Command::NoteHome {
            id,
            generation,
            polled_at,
        } => {
            ignore(engine.note_home(id, generation, polled_at));
        }
        #[cfg(test)]
        Command::Advance(now) => {
            engine.clock().set_now(now);
        }
    }
    deliver_due(engine, deliveries);
    true
}

fn deliver_due<C: Clock>(engine: &mut Engine<C>, deliveries: &HashMap<OwnerId, Arc<Slot>>) {
    for wake in engine.poll() {
        if let Some(slot) = deliveries.get(&wake.owner) {
            slot.deliver(wake);
        }
    }
}

/// A fire-and-forget result. Matching it is the use; dropping a `Copy`
/// `Result` is a no-op, and `let _` is refused on a `#[must_use]` type.
fn ignore<E>(result: Result<(), E>) {
    if let Err(_err) = result {}
}

fn enqueue(tx: &Sender<Command>, closed: &AtomicBool, command: Command) -> Result<(), EngineError> {
    if closed.load(Ordering::Acquire) {
        return Err(EngineError::Closed);
    }
    tx.send(command).map_err(|_| EngineError::Closed)
}

/// Mints owner ids and registers them. Clone it onto each home's thread.
pub struct Handle<C: Clock> {
    tx: Sender<Command>,
    closed: Arc<AtomicBool>,
    ids: IdSource,
    clock: C,
}

impl<C: Clock + Clone> Handle<C> {
    /// The clock the service was started with. A clone shares its origin.
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Mint an id and queue its registration. This does not wait for the
    /// engine to apply it.
    pub fn register(&self, class: OwnerClass) -> Result<OwnerHandle<C>, EngineError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(EngineError::Closed);
        }
        let id = self.ids.mint();
        let slot = Arc::new(Slot::new());
        enqueue(
            &self.tx,
            &self.closed,
            Command::Register {
                id,
                class,
                slot: Arc::clone(&slot),
            },
        )?;
        Ok(OwnerHandle {
            id,
            tx: self.tx.clone(),
            closed: Arc::clone(&self.closed),
            clock: self.clock.clone(),
            armed: Mutex::new(None),
            deregistered: AtomicBool::new(false),
            slot,
        })
    }
}

/// One owner. The home that holds it is the only sender for this id.
pub struct OwnerHandle<C: Clock> {
    id: OwnerId,
    tx: Sender<Command>,
    closed: Arc<AtomicBool>,
    clock: C,
    /// The deadline this handle last sent. `None` after a wake is taken,
    /// after clear, and after deregister.
    armed: Mutex<Option<Tick>>,
    deregistered: AtomicBool,
    slot: Arc<Slot>,
}

impl<C: Clock> OwnerHandle<C> {
    pub fn id(&self) -> OwnerId {
        self.id
    }

    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Queue `deadline` only when it is strictly earlier than the one this
    /// handle has armed, or when it has none.
    pub fn arm(&self, deadline: Tick) -> Result<(), EngineError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(EngineError::Closed);
        }
        if self.deregistered.load(Ordering::Acquire) {
            return Err(EngineError::UnknownOwner);
        }
        let mut armed = self.armed.lock().expect("armed lock");
        if let Some(current) = *armed {
            if deadline >= current {
                return Ok(());
            }
        }
        enqueue(
            &self.tx,
            &self.closed,
            Command::Arm {
                id: self.id,
                deadline,
            },
        )?;
        *armed = Some(deadline);
        Ok(())
    }

    pub fn clear(&self) -> Result<(), EngineError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(EngineError::Closed);
        }
        if self.deregistered.load(Ordering::Acquire) {
            return Err(EngineError::UnknownOwner);
        }
        *self.armed.lock().expect("armed lock") = None;
        enqueue(&self.tx, &self.closed, Command::Clear { id: self.id })
    }

    pub fn deregister(&self) -> Result<(), EngineError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(EngineError::Closed);
        }
        if self.deregistered.swap(true, Ordering::AcqRel) {
            return Err(EngineError::UnknownOwner);
        }
        *self.armed.lock().expect("armed lock") = None;
        enqueue(&self.tx, &self.closed, Command::Deregister { id: self.id })
    }

    /// The wake in the slot, if the engine has delivered one.
    pub fn poll_wake(&self) -> Result<Option<Wake>, EngineError> {
        match self.slot.poll()? {
            Some(wake) => {
                self.observe(&wake);
                Ok(Some(wake))
            }
            None if self.closed.load(Ordering::Acquire) => Err(EngineError::Closed),
            None => Ok(None),
        }
    }

    /// Block until a wake is delivered, the owner is deregistered, or the
    /// service is closed.
    pub fn wait_wake(&self) -> Result<Wake, EngineError> {
        let wake = self.slot.wait()?;
        self.observe(&wake);
        Ok(wake)
    }

    fn observe(&self, wake: &Wake) {
        *self.armed.lock().expect("armed lock") = None;
        let polled_at = self.clock.now();
        ignore(enqueue(
            &self.tx,
            &self.closed,
            Command::NoteHome {
                id: self.id,
                generation: wake.generation,
                polled_at,
            },
        ));
    }
}

// The paused spawn cannot be expressed by calling `start` and then holding
// the gate: the thread may already be blocked in `recv`. This constructor
// is the one that holds the gate before the thread is spawned.
#[cfg(test)]
impl<C: Clock + Clone + Send + 'static> EngineService<C> {
    fn start_paused(clock: C) -> Self {
        let (tx, rx) = mpsc::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let ids = IdSource::new();
        let engine_clock = clock.clone();
        let gate = Arc::new(Gate::new(true));
        let counts = Arc::new(Counts {
            registers: AtomicUsize::new(0),
            arms: AtomicUsize::new(0),
        });
        let thread_closed = Arc::clone(&closed);
        let thread_gate = Arc::clone(&gate);
        let thread_counts = Arc::clone(&counts);
        let thread = thread::Builder::new()
            .name("shekyl-timing".to_string())
            .spawn(move || {
                let engine = Engine::new(engine_clock);
                let finished = catch_unwind(AssertUnwindSafe(|| {
                    worker(engine, &rx, &thread_closed, &thread_gate, &thread_counts);
                }));
                if finished.is_err() {
                    std::process::abort();
                }
            })
            .expect("timing engine thread");
        Self {
            tx,
            closed,
            ids,
            clock,
            thread: Mutex::new(Some(thread)),
            gate,
            counts,
        }
    }

    fn advance(&self, now: Tick) {
        self.tx
            .send(Command::Advance(now))
            .expect("engine thread alive");
    }

    fn barrier(&self) {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(Command::Barrier(reply_tx))
            .expect("engine thread alive");
        reply_rx.recv().expect("engine thread replied");
    }

    fn fail_the_thread(&self) {
        self.tx.send(Command::Panic).expect("engine thread alive");
    }

    fn release(&self) {
        self.gate.release();
    }

    fn wait_stopped(&self) {
        if let Some(thread) = self.thread.lock().expect("thread lock").take() {
            drop(thread.join());
        }
    }

    fn registers_applied(&self) -> usize {
        self.counts.registers.load(Ordering::Relaxed)
    }

    fn arms_applied(&self) -> usize {
        self.counts.arms.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::sync::mpsc;
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

    #[test]
    fn every_handle_refuses_once_the_service_is_closed() {
        let service = EngineService::start(ManualClock::new(Tick::new(0)));
        let first = service.handle();
        let second = service.handle();
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
        match owner.poll_wake() {
            Ok(None) | Err(EngineError::Closed) => {}
            Ok(Some(wake)) => panic!("queued arm was applied: {wake:?}"),
            Err(err) => panic!("unexpected {err:?}"),
        }
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
        assert_eq!(
            status.signal(),
            Some(6),
            "expected SIGABRT from process::abort, got {status:?}"
        );
    }
}
