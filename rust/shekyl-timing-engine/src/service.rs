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
    Lateness {
        class: OwnerClass,
        reply: Sender<crate::ClassLateness>,
    },
    #[cfg(test)]
    Panic,
}

/// A pending wake and the terminal mark are independent. Close or
/// deregister while a wake is sitting in the slot must not drop the
/// wake, and must not leave the slot empty with nobody left to seal it.
#[derive(Clone, Copy)]
enum SlotState {
    Empty,
    Wake(Wake),
    Closed,
    Gone,
    WakeThenClosed(Wake),
    WakeThenGone(Wake),
}

enum Terminal {
    Closed,
    Gone,
}

struct Slot {
    state: Mutex<SlotState>,
    cvar: Condvar,
    /// Set while `wait` is blocked, so a test can close only after the
    /// home is parked. Not a production signal.
    #[cfg(test)]
    parked: AtomicBool,
}

impl Slot {
    fn new() -> Self {
        Self {
            state: Mutex::new(SlotState::Empty),
            cvar: Condvar::new(),
            #[cfg(test)]
            parked: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    fn is_parked(&self) -> bool {
        self.parked.load(Ordering::Acquire)
    }

    /// A poisoned lock means a home panicked while holding it. The next
    /// deliver on this thread then panics, and the process aborts. Release
    /// builds already abort on any panic, so this is the same outcome.
    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().expect("slot lock poisoned; aborting")
    }

    fn deliver(&self, wake: Wake) {
        let mut state = self.lock();
        match *state {
            SlotState::Empty => {
                *state = SlotState::Wake(wake);
                self.cvar.notify_one();
            }
            SlotState::Wake(_) => *state = SlotState::Wake(wake),
            SlotState::Closed
            | SlotState::Gone
            | SlotState::WakeThenClosed(_)
            | SlotState::WakeThenGone(_) => {}
        }
    }

    fn poll(&self) -> Result<Option<Wake>, EngineError> {
        let mut state = self.lock();
        Self::take(&mut state)
    }

    /// Block until a wake is handed out, the slot is terminal, or `idle`
    /// says the handle itself is done. `idle` runs while the slot lock is
    /// held, so a seal cannot land between the check and the wait.
    fn wait(&self, idle: impl Fn() -> Result<(), EngineError>) -> Result<Wake, EngineError> {
        let mut state = self.lock();
        loop {
            match Self::take(&mut state)? {
                Some(wake) => return Ok(wake),
                None => {
                    idle()?;
                    #[cfg(test)]
                    self.parked.store(true, Ordering::Release);
                    state = self.cvar.wait(state).expect("slot lock poisoned; aborting");
                    #[cfg(test)]
                    self.parked.store(false, Ordering::Release);
                }
            }
        }
    }

    fn take(state: &mut SlotState) -> Result<Option<Wake>, EngineError> {
        match std::mem::replace(state, SlotState::Empty) {
            SlotState::Wake(wake) => Ok(Some(wake)),
            SlotState::WakeThenClosed(wake) => {
                *state = SlotState::Closed;
                Ok(Some(wake))
            }
            SlotState::WakeThenGone(wake) => {
                *state = SlotState::Gone;
                Ok(Some(wake))
            }
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

    fn seal(&self, terminal: Terminal) {
        let mut state = self.lock();
        let next = match (*state, terminal) {
            (SlotState::Empty, Terminal::Closed) => SlotState::Closed,
            (SlotState::Empty, Terminal::Gone) => SlotState::Gone,
            (SlotState::Wake(wake), Terminal::Closed) => SlotState::WakeThenClosed(wake),
            (SlotState::Wake(wake), Terminal::Gone) => SlotState::WakeThenGone(wake),
            _ => return,
        };
        *state = next;
        self.cvar.notify_all();
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
        slot.seal(Terminal::Closed);
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
            while let Ok(queued) = rx.try_recv() {
                seal_discarded_register(queued);
            }
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
        #[cfg(test)]
        Command::Lateness { class, reply } => {
            ignore(reply.send(engine.lateness(class).clone()));
            return true;
        }
        other if closed.load(Ordering::Acquire) => {
            seal_discarded_register(other);
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
                slot.seal(Terminal::Gone);
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

/// After every command, not once per sleep. A burst must not hold a due
/// wake until the mailbox has drained.
/// A `Register` that close drops never enters `deliveries`, so the
/// worker's shutdown seal would not see its slot. Seal it here or a
/// home already blocked in `wait_wake` never wakes.
fn seal_discarded_register(command: Command) {
    if let Command::Register { slot, .. } = command {
        slot.seal(Terminal::Closed);
    }
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
    ///
    /// A wake already waiting is handed out once, even after close or
    /// deregister. The next call then returns [`EngineError::Closed`] or
    /// [`EngineError::UnknownOwner`]. An empty slot checks this handle's
    /// own flags, so a deregistered home does not see `Ok(None)`.
    pub fn poll_wake(&self) -> Result<Option<Wake>, EngineError> {
        match self.slot.poll()? {
            Some(wake) => {
                self.observe(&wake);
                Ok(Some(wake))
            }
            None => self.idle().map(|()| None),
        }
    }

    /// Block until a wake is delivered, the owner is deregistered, or the
    /// service is closed.
    pub fn wait_wake(&self) -> Result<Wake, EngineError> {
        let wake = self.slot.wait(|| self.idle())?;
        self.observe(&wake);
        Ok(wake)
    }

    fn idle(&self) -> Result<(), EngineError> {
        if self.deregistered.load(Ordering::Acquire) {
            Err(EngineError::UnknownOwner)
        } else if self.closed.load(Ordering::Acquire) {
            Err(EngineError::Closed)
        } else {
            Ok(())
        }
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

    fn lateness(&self, class: OwnerClass) -> crate::ClassLateness {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(Command::Lateness {
                class,
                reply: reply_tx,
            })
            .expect("engine thread alive");
        reply_rx.recv().expect("engine thread replied")
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
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

    /// The second wait is the bug: a wake was in the slot at shutdown, so
    /// seal used to leave the slot empty after that wake was taken, and
    /// the engine thread was already gone.
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
}
