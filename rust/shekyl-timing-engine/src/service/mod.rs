// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The engine service from `P2P_TIMING_ENGINE.md`'s addendum.
//!
//! One std thread owns the [`Engine`](crate::Engine). Homes send on a
//! mailbox and do not wait for the engine to apply the command. The
//! handle drops an arm that is not strictly earlier than the one it
//! remembers. That memory clears when the home takes the wake for that
//! arm, and on clear and deregister. A wake that was already waiting
//! carries the older arm's token, so taking it leaves the newer arm
//! in place.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::{
    Clock, Engine, EngineError, Generation, IdSource, OwnerClass, OwnerId, OwnerMint, Tick, Wake,
};

/// Which arm a handle sent. The engine thread copies it onto the wake
/// of the generation that arm created. A no-op arm does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ArmToken(u64);

/// A wake and the arm it belongs to.
///
/// The token stays here. [`Wake`] is the core's value, and the core
/// does not know which handle sent the arm.
#[derive(Clone, Copy, Debug)]
struct Delivered {
    wake: Wake,
    token: ArmToken,
}

enum Command {
    Register {
        minted: OwnerMint,
        class: OwnerClass,
        slot: Arc<Slot>,
    },
    Arm {
        id: OwnerId,
        deadline: Tick,
        token: ArmToken,
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

enum Terminal {
    Closed,
    Gone,
}

/// A waiting wake and a terminal mark are independent. Close or
/// deregister while a wake is waiting keeps that wake, and leaves the
/// mark so the next wait does not block after the wake is taken.
struct SlotContents {
    pending: Option<Delivered>,
    terminal: Option<Terminal>,
}

struct Slot {
    contents: Mutex<SlotContents>,
    cvar: Condvar,
    /// Set while `wait` is blocked, so a test can close only after the
    /// home is parked.
    #[cfg(test)]
    parked: AtomicBool,
}

impl Slot {
    fn new() -> Self {
        Self {
            contents: Mutex::new(SlotContents {
                pending: None,
                terminal: None,
            }),
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
    fn lock(&self) -> std::sync::MutexGuard<'_, SlotContents> {
        self.contents.lock().expect("slot lock poisoned; aborting")
    }

    fn deliver(&self, delivered: Delivered) {
        let mut contents = self.lock();
        if contents.terminal.is_some() {
            return;
        }
        let notify = contents.pending.is_none();
        contents.pending = Some(delivered);
        if notify {
            self.cvar.notify_one();
        }
    }

    fn poll(&self) -> Result<Option<Delivered>, EngineError> {
        let mut contents = self.lock();
        Self::take(&mut contents)
    }

    /// Block until a wake is handed out, the slot is terminal, or `idle`
    /// says the handle itself is done. `idle` runs while the slot lock is
    /// held, so a seal cannot land between the check and the wait.
    fn wait(&self, idle: impl Fn() -> Result<(), EngineError>) -> Result<Delivered, EngineError> {
        let mut contents = self.lock();
        loop {
            match Self::take(&mut contents)? {
                Some(delivered) => return Ok(delivered),
                None => {
                    idle()?;
                    #[cfg(test)]
                    self.parked.store(true, Ordering::Release);
                    contents = self
                        .cvar
                        .wait(contents)
                        .expect("slot lock poisoned; aborting");
                    #[cfg(test)]
                    self.parked.store(false, Ordering::Release);
                }
            }
        }
    }

    fn take(contents: &mut SlotContents) -> Result<Option<Delivered>, EngineError> {
        if let Some(delivered) = contents.pending.take() {
            return Ok(Some(delivered));
        }
        match contents.terminal {
            Some(Terminal::Closed) => Err(EngineError::Closed),
            Some(Terminal::Gone) => Err(EngineError::UnknownOwner),
            None => Ok(None),
        }
    }

    fn seal(&self, terminal: Terminal) {
        let mut contents = self.lock();
        if contents.terminal.is_some() {
            return;
        }
        contents.terminal = Some(terminal);
        self.cvar.notify_all();
    }
}

/// The engine thread's record of one owner: where to deliver, and the
/// token of the arm whose generation is current.
struct OwnerSlot {
    slot: Arc<Slot>,
    generation: Option<Generation>,
    token: Option<ArmToken>,
}

impl OwnerSlot {
    fn new(slot: Arc<Slot>) -> Self {
        Self {
            slot,
            generation: None,
            token: None,
        }
    }

    /// Remember `token` when `generation` is a new arm.
    ///
    /// A no-op arm returns the generation already stored. Replacing the
    /// token then would make the live wake look like the rejected arm.
    fn note_arm(&mut self, generation: Generation, token: ArmToken) -> bool {
        if self.generation == Some(generation) {
            return false;
        }
        self.generation = Some(generation);
        self.token = Some(token);
        true
    }

    fn stamp(&self, wake: Wake) -> Option<Delivered> {
        let token = self
            .token
            .filter(|_| self.generation == Some(wake.generation))?;
        Some(Delivered { wake, token })
    }
}

/// The deadline this handle has sent, and which arm that was.
///
/// Taking a wake clears `armed` only when the wake carries the same
/// token. `clear` and `deregister` clear it themselves.
struct ArmMemory {
    armed: Option<Armed>,
    next_token: u64,
}

#[derive(Clone, Copy)]
struct Armed {
    deadline: Tick,
    token: ArmToken,
}

impl ArmMemory {
    fn new() -> Self {
        Self {
            armed: None,
            next_token: 1,
        }
    }

    fn issue(&mut self) -> ArmToken {
        let token = ArmToken(self.next_token);
        self.next_token = self
            .next_token
            .checked_add(1)
            .expect("arm token space exhausted");
        token
    }

    fn accepts(&self, deadline: Tick) -> bool {
        self.armed.is_none_or(|armed| deadline < armed.deadline)
    }

    fn remember(&mut self, deadline: Tick, token: ArmToken) {
        self.armed = Some(Armed { deadline, token });
    }

    fn forget(&mut self) {
        self.armed = None;
    }

    fn observe(&mut self, delivered: &Delivered) {
        if self
            .armed
            .is_some_and(|armed| armed.token == delivered.token)
        {
            self.armed = None;
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
        Self::spawn(
            clock,
            Arc::new(|| std::process::abort()),
            #[cfg(test)]
            false,
        )
    }

    fn spawn(
        clock: C,
        terminal: Arc<dyn Fn() + Send + Sync>,
        #[cfg(test)] hold_gate: bool,
    ) -> Self {
        let (tx, rx) = mpsc::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let ids = IdSource::new();
        let engine_clock = clock.clone();
        #[cfg(test)]
        let gate = Arc::new(Gate::new(hold_gate));
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
    let mut deliveries: HashMap<OwnerId, OwnerSlot> = HashMap::new();
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
    for owner in deliveries.values() {
        owner.slot.seal(Terminal::Closed);
    }
    engine.close();
}

fn step<C: Clock>(
    engine: &mut Engine<C>,
    rx: &Receiver<Command>,
    closed: &AtomicBool,
    deliveries: &mut HashMap<OwnerId, OwnerSlot>,
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
    deliveries: &mut HashMap<OwnerId, OwnerSlot>,
    command: Command,
    #[cfg(test)] counts: &Counts,
) -> bool {
    match command {
        Command::Shutdown => {
            while let Ok(queued) = rx.try_recv() {
                seal_unapplied(queued);
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
            seal_unapplied(other);
            return true;
        }
        Command::Register {
            minted,
            class,
            slot,
        } => {
            let id = minted.id();
            match engine.register(minted, class) {
                Ok(()) => {
                    deliveries.insert(id, OwnerSlot::new(slot));
                    #[cfg(test)]
                    counts.registers.fetch_add(1, Ordering::Relaxed);
                }
                // The handle has already been returned. A registration the
                // engine refuses must still wake a home blocked in `wait`.
                Err(_) => slot.seal(Terminal::Closed),
            }
        }
        Command::Arm {
            id,
            deadline,
            token,
        } => {
            if let Ok(generation) = engine.arm(id, deadline) {
                if let Some(owner) = deliveries.get_mut(&id) {
                    let advanced = owner.note_arm(generation, token);
                    #[cfg(test)]
                    if advanced {
                        counts.arms.fetch_add(1, Ordering::Relaxed);
                    }
                    #[cfg(not(test))]
                    let _ = advanced;
                }
            }
        }
        Command::Clear { id } => {
            ignore(engine.clear(id));
        }
        Command::Deregister { id } => {
            ignore(engine.deregister(id));
            if let Some(owner) = deliveries.remove(&id) {
                owner.slot.seal(Terminal::Gone);
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

/// A `Register` that is not applied never enters `deliveries`. Seal its
/// slot here, or a home already blocked in `wait` never wakes.
fn seal_unapplied(command: Command) {
    if let Command::Register { slot, .. } = command {
        slot.seal(Terminal::Closed);
    }
}

/// After every command, not once per sleep. A burst must not hold a due
/// wake until the mailbox has drained.
fn deliver_due<C: Clock>(engine: &mut Engine<C>, deliveries: &HashMap<OwnerId, OwnerSlot>) {
    for wake in engine.poll() {
        let Some(owner) = deliveries.get(&wake.owner) else {
            continue;
        };
        let delivered = owner
            .stamp(wake)
            .expect("a due wake is an arm this thread stamped");
        owner.slot.deliver(delivered);
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
        let minted = self.ids.mint()?;
        let id = minted.id();
        let slot = Arc::new(Slot::new());
        enqueue(
            &self.tx,
            &self.closed,
            Command::Register {
                minted,
                class,
                slot: Arc::clone(&slot),
            },
        )?;
        Ok(OwnerHandle {
            id,
            tx: self.tx.clone(),
            closed: Arc::clone(&self.closed),
            clock: self.clock.clone(),
            memory: Mutex::new(ArmMemory::new()),
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
    memory: Mutex<ArmMemory>,
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
        self.ensure_open()?;
        let mut memory = self.memory.lock().expect("arm memory");
        if !memory.accepts(deadline) {
            return Ok(());
        }
        let token = memory.issue();
        enqueue(
            &self.tx,
            &self.closed,
            Command::Arm {
                id: self.id,
                deadline,
                token,
            },
        )?;
        memory.remember(deadline, token);
        Ok(())
    }

    pub fn clear(&self) -> Result<(), EngineError> {
        self.ensure_open()?;
        self.memory.lock().expect("arm memory").forget();
        enqueue(&self.tx, &self.closed, Command::Clear { id: self.id })
    }

    pub fn deregister(&self) -> Result<(), EngineError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(EngineError::Closed);
        }
        if self.deregistered.swap(true, Ordering::AcqRel) {
            return Err(EngineError::UnknownOwner);
        }
        self.memory.lock().expect("arm memory").forget();
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
            Some(delivered) => {
                self.observe(&delivered);
                Ok(Some(delivered.wake))
            }
            None => self.idle().map(|()| None),
        }
    }

    /// Block until a wake is delivered, the owner is deregistered, or the
    /// service is closed.
    pub fn wait_wake(&self) -> Result<Wake, EngineError> {
        let delivered = self.slot.wait(|| self.idle())?;
        self.observe(&delivered);
        Ok(delivered.wake)
    }

    fn ensure_open(&self) -> Result<(), EngineError> {
        if self.closed.load(Ordering::Acquire) {
            Err(EngineError::Closed)
        } else if self.deregistered.load(Ordering::Acquire) {
            Err(EngineError::UnknownOwner)
        } else {
            Ok(())
        }
    }

    fn idle(&self) -> Result<(), EngineError> {
        self.ensure_open()
    }

    fn observe(&self, delivered: &Delivered) {
        self.memory.lock().expect("arm memory").observe(delivered);
        let polled_at = self.clock.now();
        ignore(enqueue(
            &self.tx,
            &self.closed,
            Command::NoteHome {
                id: self.id,
                generation: delivered.wake.generation,
                polled_at,
            },
        ));
    }
}

#[cfg(test)]
impl<C: Clock + Clone + Send + 'static> EngineService<C> {
    fn start_paused(clock: C) -> Self {
        Self::spawn(clock, Arc::new(|| std::process::abort()), true)
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
mod tests;
