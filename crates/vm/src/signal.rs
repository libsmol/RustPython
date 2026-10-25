use core::{
    cell::{Cell, RefCell},
    fmt,
    ops::{Deref, DerefMut, Index, IndexMut, Range},
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};
use std::sync::mpsc;
#[cfg(not(all(target_os = "wasi", feature = "host_env")))]
use std::time::Instant;

#[cfg(windows)]
use core::sync::atomic::AtomicIsize;

use crate::{PyObjectRef, PyResult, TryFromBorrowedObject, TryFromObject, VirtualMachine};

pub(crate) const NSIG: usize = 64;

#[cfg(not(feature = "threading"))]
bitflagset::bitflag! {
    /// Eval-breaker bits checked once per bytecode instruction.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[repr(u8)]
    enum EvalBreakerFlag {
        Signal = 0,
    }
}

#[cfg(feature = "threading")]
bitflagset::bitflag! {
    /// Eval-breaker bits checked once per bytecode instruction.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[repr(u8)]
    enum EvalBreakerFlag {
        Signal = 0,
        Qsbr = 1,
        Stop = 3,
        Finalizing = 4,
    }
}

bitflagset::bitflagset! {
    #[derive(Copy, Clone, PartialEq, Eq)]
    struct EvalBreakerBits(u8): EvalBreakerFlag
}

bitflagset::atomic_bitflagset!(struct EvalBreaker(AtomicU8) on EvalBreakerBits);

/// Signal handlers and QSBR set bits with fetch_or (async-signal-safe,
/// lock-free); consumers clear only their own bit with fetch_and.
static EVAL_BREAKER: EvalBreaker = EvalBreaker::new();

#[expect(
    clippy::declare_interior_mutable_const,
    reason = "workaround for const array repeat limitation (rust issue #79270)"
)]
const ATOMIC_FALSE: AtomicBool = AtomicBool::new(false);

pub(crate) static TRIGGERS: [AtomicBool; NSIG] = [ATOMIC_FALSE; NSIG];

#[cfg(windows)]
static SIGINT_EVENT: AtomicIsize = AtomicIsize::new(0);

/// `_PyRuntime.signals.unhandled_keyboard_interrupt`
static UNHANDLED_KEYBOARD_INTERRUPT: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_unhandled_keyboard_interrupt() {
    UNHANDLED_KEYBOARD_INTERRUPT.store(true, Ordering::Relaxed);
}

pub(crate) fn clear_unhandled_keyboard_interrupt() {
    UNHANDLED_KEYBOARD_INTERRUPT.store(false, Ordering::Relaxed);
}

pub(crate) fn unhandled_keyboard_interrupt() -> bool {
    UNHANDLED_KEYBOARD_INTERRUPT.load(Ordering::Relaxed)
}

/// exit_sigint: exit through the default SIGINT handler so that the parent
/// process sees that a KeyboardInterrupt went unhandled.
pub(crate) fn exit_sigint() -> u32 {
    cfg_select! {
        unix => {
            if crate::host_env::signal::set_sigint_default_onstack().is_ok() {
                let _ = crate::host_env::signal::send_sigint_to_self();
            }
            libc::SIGINT as u32 + 128
        }
        // STATUS_CONTROL_C_EXIT
        windows => 0xC000013A,
        _ => 2 + 128,
    }
}

thread_local! {
    /// Prevent recursive signal handler invocation. When a Python signal
    /// handler is running, new signals are deferred until it completes.
    static IN_SIGNAL_HANDLER: Cell<bool> = const { Cell::new(false) };
}

struct SignalHandlerGuard;

impl Drop for SignalHandlerGuard {
    fn drop(&mut self) {
        IN_SIGNAL_HANDLER.with(|h| h.set(false));
    }
}

#[cfg_attr(feature = "flame-it", flame)]
#[inline(always)]
pub fn check_signals(vm: &VirtualMachine) -> PyResult<()> {
    if vm.signal_handlers.get().is_none() {
        return Ok(());
    }

    // Read-only check first: avoids cache-line invalidation on every
    // instruction when no signal is pending (the common case).
    if !EVAL_BREAKER.contains(&EvalBreakerFlag::Signal) {
        return Ok(());
    }

    // Atomic RMW only when a signal is actually pending.
    if !EVAL_BREAKER.remove(EvalBreakerFlag::Signal) {
        return Ok(());
    }

    trigger_signals(vm)
}

#[inline(never)]
#[cold]
fn trigger_signals(vm: &VirtualMachine) -> PyResult<()> {
    if IN_SIGNAL_HANDLER.with(|h| h.replace(true)) {
        // Already inside a signal handler — defer pending signals
        set_triggered();
        return Ok(());
    }
    let _guard = SignalHandlerGuard;

    let can_handle_signals = vm.is_main_thread() && vm.state.is_main_interpreter();
    if can_handle_signals {
        let signal_handlers = vm
            .signal_handlers
            .get()
            .expect("should never fail since we check above");

        for (signum, trigger) in TRIGGERS.iter().enumerate().skip(1) {
            let triggered = trigger.swap(false, Ordering::Relaxed);
            if !triggered {
                continue;
            }

            // SAFETY: TRIGGERS has the same length as the signal_handlers
            let signum = unsafe { SignalNum::new_unchecked(signum as i32) };

            // Read the handler out and drop the borrow before running it. A
            // handler is free to call signal.signal(), which takes the same cell
            // mutably, and a live read borrow turns that into a panic.
            let handler = signal_handlers.borrow()[signum].clone();

            if let Some(handler) = handler
                && let Some(callable) = handler.to_callable()
                && let Err(exc) = callable.invoke((signum.as_i32(), vm.ctx.none()), vm)
            {
                // On error, re-schedule a call to trigger_signals() for the
                // remaining signals and the pending wakeup errors.
                set_triggered();
                return Err(exc);
            }
        }
    } else {
        let os_signals_pending = TRIGGERS
            .iter()
            .skip(1)
            .any(|trigger| trigger.load(Ordering::Relaxed));
        #[cfg(all(feature = "host_env", any(unix, windows)))]
        let os_signals_pending =
            os_signals_pending || crate::stdlib::_signal::_signal::wakeup_errors_pending();
        if os_signals_pending {
            // Leave OS signals for the main interpreter's main thread. Re-arm
            // before running VM-local callbacks, which may raise.
            set_triggered();
        }
    }

    if let Some(signal_rx) = &vm.signal_rx {
        for f in signal_rx.rx.try_iter() {
            if let Err(exc) = f(vm) {
                set_triggered();
                return Err(exc);
            }
        }
    }

    // Wakeup fd errors are pending calls that only the main interpreter's
    // main thread runs.
    #[cfg(all(feature = "host_env", any(unix, windows)))]
    if can_handle_signals {
        crate::stdlib::_signal::_signal::report_wakeup_errors(vm);
    }

    Ok(())
}

pub(crate) fn set_triggered() {
    // fetch_or (not store) so a signal handler never clobbers the QSBR bit;
    // this compiles to a lock-free RMW, safe to call from a signal handler.
    EVAL_BREAKER.insert(EvalBreakerFlag::Signal);
}

/// Any eval-breaker bit pending? One relaxed load; checked per instruction.
#[inline(always)]
pub(crate) fn eval_breaker_pending() -> bool {
    !EVAL_BREAKER.is_empty()
}

#[cfg(all(target_os = "wasi", feature = "host_env"))]
pub(crate) use host_interrupt::host_interrupted;
#[cfg(all(target_os = "wasi", feature = "host_env"))]
pub use host_interrupt::{has_interrupt_check, set_interrupt_check, slice_ended, wait_slice};

#[cfg(not(all(target_os = "wasi", feature = "host_env")))]
#[inline]
#[must_use]
pub fn has_interrupt_check() -> bool {
    false
}

/// Elsewhere a signal wakes a blocking wait, so it can run up to its deadline.
#[cfg(not(all(target_os = "wasi", feature = "host_env")))]
#[inline]
#[must_use]
pub fn wait_slice(deadline: Option<Instant>) -> Option<Instant> {
    deadline
}

#[cfg(not(all(target_os = "wasi", feature = "host_env")))]
#[inline]
pub fn slice_ended(_vm: &VirtualMachine) -> PyResult<()> {
    Ok(())
}

/// WASI delivers no signals, so a host interrupts running code through a check it registers.
#[cfg(all(target_os = "wasi", feature = "host_env"))]
mod host_interrupt {
    use super::SignalNum;
    use crate::{PyResult, VirtualMachine};
    use core::cell::Cell;
    use core::time::Duration;
    use std::sync::OnceLock;
    use std::time::Instant;

    /// Instructions run between two calls to the check
    const CHECK_INTERVAL: u32 = 4096;

    /// How long a blocking wait runs before it comes back to call the check
    const WAIT_SLICE: Duration = Duration::from_millis(50);

    static CHECK: OnceLock<fn() -> bool> = OnceLock::new();

    thread_local! {
        static UNTIL_CHECK: Cell<u32> = const { Cell::new(0) };
    }

    /// Lets a WASI host interrupt running code.
    ///
    /// The interpreter calls `check` every few thousand instructions and while
    /// `time.sleep`, blocking sockets, `select` and `poll` wait. When it returns
    /// `true`, SIGINT is raised as if the process had received it, so the
    /// Python handler runs, which by default raises `KeyboardInterrupt`. A
    /// check can only be set once, and a second one is handed back.
    pub fn set_interrupt_check(check: fn() -> bool) -> Result<(), fn() -> bool> {
        CHECK.set(check)
    }

    #[must_use]
    pub fn has_interrupt_check() -> bool {
        CHECK.get().is_some()
    }

    /// The deadline for the next stretch of a blocking wait. Nothing can wake a
    /// wait on WASI, so with a check registered it ends after a short slice.
    #[must_use]
    pub fn wait_slice(deadline: Option<Instant>) -> Option<Instant> {
        if !has_interrupt_check() {
            return deadline;
        }
        let slice = Instant::now() + WAIT_SLICE;
        Some(deadline.map_or(slice, |deadline| deadline.min(slice)))
    }

    /// Calls the check when a slice from [`wait_slice`] ends, so an interrupt it
    /// reports is raised as a signal received during the wait would be.
    pub fn slice_ended(vm: &VirtualMachine) -> PyResult<()> {
        if ask_host() {
            vm.check_signals()
        } else {
            Ok(())
        }
    }

    /// Counts down to the next call of the check, and runs on every instruction.
    #[inline(always)]
    pub(crate) fn host_interrupted() -> bool {
        if !has_interrupt_check() {
            return false;
        }
        let left = UNTIL_CHECK.get();
        if left > 0 {
            UNTIL_CHECK.set(left - 1);
            return false;
        }
        ask_host()
    }

    /// Calls the check now, tripping SIGINT when it reports an interrupt.
    #[inline(never)]
    #[cold]
    fn ask_host() -> bool {
        UNTIL_CHECK.set(CHECK_INTERVAL);
        let Some(check) = CHECK.get() else {
            return false;
        };
        if !check() {
            return false;
        }
        crate::stdlib::_signal::_signal::run_signal(SignalNum::SIGINT.as_i32());
        true
    }

    #[cfg(test)]
    mod tests {
        use super::set_interrupt_check;
        use crate::{AsObject, Interpreter, PyResult};
        use core::time::Duration;
        use std::sync::Mutex;
        use std::time::Instant;

        /// When the check reports an interrupt, which it does once
        static DUE: Mutex<Option<Instant>> = Mutex::new(None);

        fn due() -> bool {
            let mut due = DUE.lock().unwrap();
            match *due {
                Some(at) if Instant::now() >= at => {
                    *due = None;
                    true
                }
                _ => false,
            }
        }

        /// Runs `source` with an interrupt due 100 ms in, returning the name of
        /// the exception it ended with
        fn run(source: &str) -> Option<String> {
            let _ = set_interrupt_check(due);
            Interpreter::without_stdlib(Default::default()).enter(|vm| {
                let scope = vm.new_scope_with_builtins();
                *DUE.lock().unwrap() = Some(Instant::now() + Duration::from_millis(100));
                let result: PyResult = vm.run_string(scope, source, "<unittest>");
                *DUE.lock().unwrap() = None;
                result.err().map(|exc| exc.class().name().to_string())
            })
        }

        #[test]
        fn busy_loop_interrupted() {
            let raised = run("while True: pass");
            assert_eq!(raised.as_deref(), Some("KeyboardInterrupt"));
        }

        #[test]
        fn sleep_interrupted() {
            let started = Instant::now();
            let raised = run("import time\ntime.sleep(30)");
            assert_eq!(raised.as_deref(), Some("KeyboardInterrupt"));
            assert!(started.elapsed() < Duration::from_secs(10));
        }

        #[test]
        fn sleep_resumes_after_handler() {
            let source = "\
import _signal, time
started = time.monotonic()
hits = []
_signal.signal(_signal.SIGINT, lambda signum, frame: hits.append(time.monotonic() - started))
time.sleep(0.5)
assert len(hits) == 1 and hits[0] < 0.4, hits
assert time.monotonic() - started >= 0.5
";
            assert_eq!(run(source), None);
        }
    }
}

/// Extra eval-breaker bits used only when more than one thread can run.
#[cfg(feature = "threading")]
mod mt {
    use super::{EVAL_BREAKER, EvalBreakerFlag};

    /// QSBR has retired allocations pending reclamation.
    pub(crate) fn set_qsbr_bit() {
        EVAL_BREAKER.insert(EvalBreakerFlag::Qsbr);
    }

    pub(crate) fn clear_qsbr_bit() {
        EVAL_BREAKER.remove(EvalBreakerFlag::Qsbr);
    }

    pub(crate) fn qsbr_bit_set() -> bool {
        EVAL_BREAKER.contains(&EvalBreakerFlag::Qsbr)
    }

    /// Record that some thread's `stop_requested` flag may be set. Shared by
    /// every thread rather than being per-thread: the fast path checked once
    /// per bytecode instruction becomes a single relaxed load of this word.
    /// Sticky until `start_the_world`/`reset_after_fork` clears it.
    pub(crate) fn set_stop_bit() {
        EVAL_BREAKER.insert(EvalBreakerFlag::Stop);
    }

    /// Clear the shared stop-the-world bit. Only safe to call from
    /// `start_the_world`/`reset_after_fork`.
    pub(crate) fn clear_stop_bit() {
        EVAL_BREAKER.remove(EvalBreakerFlag::Stop);
    }

    /// Record that finalization has begun (`Interpreter::finalize`). Set once
    /// and never cleared.
    pub(crate) fn set_finalizing_bit() {
        EVAL_BREAKER.insert(EvalBreakerFlag::Finalizing);
    }

    /// Drop every process-wide eval-breaker bit. Tests that assert a single
    /// thread's `stop_requested` must not trip `eval_breaker_pending` have to
    /// start from a clean word: cargo's Windows runner shares the process
    /// across `#[test]` functions, so a sibling can leave SIGNAL/QSBR/STOP.
    #[cfg(test)]
    pub(crate) fn clear_eval_breaker_for_test() {
        EVAL_BREAKER.clear();
    }
}

#[cfg(feature = "threading")]
pub(crate) use mt::{
    clear_qsbr_bit, clear_stop_bit, qsbr_bit_set, set_finalizing_bit, set_qsbr_bit, set_stop_bit,
};

#[cfg(all(test, feature = "threading"))]
pub(crate) use mt::clear_eval_breaker_for_test;

/// Reset all signal trigger state after fork in child process.
/// Stale triggers from the parent must not fire in the child.
#[cfg(all(unix, feature = "host_env"))]
pub(crate) fn clear_after_fork() {
    EVAL_BREAKER.remove(EvalBreakerFlag::Signal);
    for trigger in &TRIGGERS {
        trigger.store(false, Ordering::Relaxed);
    }
}

/// A valid signal number.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SignalNum(i32);

impl SignalNum {
    pub(crate) const VALID_RANGE: Range<i32> = 1..NSIG as i32;

    /// Alias for:
    /// ```rust
    /// # use rustpython_vm::signal::SignalNum;
    ///
    /// unsafe { SignalNum::new_unchecked(libc::SIGINT) };
    /// ```
    #[cfg(any(unix, windows))]
    #[allow(dead_code, reason = "Not used on all platforms")]
    pub(crate) const SIGINT: Self = Self(libc::SIGINT);

    #[cfg(all(target_os = "wasi", feature = "host_env"))]
    #[allow(dead_code, reason = "Not used on all platforms")]
    pub(crate) const SIGINT: Self = Self(rustpython_host_env::signal::SIGINT);

    /// Construct [`Self`] without any validation on the signalnum value.
    ///
    /// # Safety
    ///
    /// Caller's responsibility to ensure the signal num is valid.
    #[must_use]
    pub const unsafe fn new_unchecked(value: i32) -> Self {
        Self(value)
    }

    /// Get the self as an [`i32`].
    #[must_use]
    pub const fn as_i32(&self) -> i32 {
        self.0
    }

    /// Get the self as an [`usize`].
    #[must_use]
    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for SignalNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<SignalNum> for i32 {
    fn from(signalnum: SignalNum) -> Self {
        signalnum.as_i32()
    }
}

impl TryFrom<i32> for SignalNum {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let bounds = cfg_select! {
            all(windows, feature = "host_env") => rustpython_host_env::signal::VALID_SIGNALS,
            _ => Self::VALID_RANGE,
        };

        if bounds.contains(&value) {
            Ok(Self(value))
        } else {
            Err("signal number out of range".into())
        }
    }
}

impl TryFromObject for SignalNum {
    fn try_from_object(vm: &VirtualMachine, obj: PyObjectRef) -> PyResult<Self> {
        Self::try_from(i32::try_from_borrowed_object(vm, &obj)?)
            .map_err(|msg| vm.new_value_error(msg))
    }
}

/// Similar to `PyErr_SetInterruptEx` in CPython
///
/// Missing signal handler for the given signal number is silently ignored.
#[cfg(all(not(target_arch = "wasm32"), feature = "host_env"))]
pub fn set_interrupt_ex(signum: SignalNum) -> PyResult<()> {
    use crate::stdlib::_signal::_signal::{SIG_DFL, SIG_IGN, run_signal};

    match signum.as_usize() {
        SIG_DFL | SIG_IGN => Ok(()),
        _ => {
            // interrupt the main thread with given signal number
            run_signal(signum.into());
            Ok(())
        }
    }
}

pub type UserSignal = Box<dyn FnOnce(&VirtualMachine) -> PyResult<()> + Send>;

#[derive(Clone, Debug)]
pub struct UserSignalSender {
    tx: mpsc::Sender<UserSignal>,
}

#[derive(Debug)]
pub struct UserSignalReceiver {
    rx: mpsc::Receiver<UserSignal>,
}

impl UserSignalSender {
    pub fn send(&self, sig: UserSignal) -> Result<(), UserSignalSendError> {
        self.tx
            .send(sig)
            .map_err(|mpsc::SendError(sig)| UserSignalSendError(sig))?;
        set_triggered();
        Ok(())
    }
}

pub struct UserSignalSendError(pub UserSignal);

impl fmt::Debug for UserSignalSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserSignalSendError")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for UserSignalSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sending a signal to a exited vm")
    }
}

#[must_use]
pub fn user_signal_channel() -> (UserSignalSender, UserSignalReceiver) {
    let (tx, rx) = mpsc::channel();
    (UserSignalSender { tx }, UserSignalReceiver { rx })
}

#[cfg(windows)]
pub fn set_sigint_event(handle: isize) {
    SIGINT_EVENT.store(handle, Ordering::Release);
}

#[cfg(windows)]
pub fn get_sigint_event() -> Option<isize> {
    let handle = SIGINT_EVENT.load(Ordering::Acquire);
    if handle == 0 { None } else { Some(handle) }
}

pub struct SignalHandlersInner([Option<PyObjectRef>; NSIG]);

impl Default for SignalHandlersInner {
    fn default() -> Self {
        Self([const { None }; NSIG])
    }
}

impl Index<SignalNum> for SignalHandlersInner {
    type Output = Option<PyObjectRef>;

    fn index(&self, index: SignalNum) -> &Self::Output {
        &self.0[index.as_usize()]
    }
}

impl IndexMut<SignalNum> for SignalHandlersInner {
    fn index_mut(&mut self, index: SignalNum) -> &mut Self::Output {
        &mut self.0[index.as_usize()]
    }
}

pub struct SignalHandlers(Box<RefCell<SignalHandlersInner>>);

impl Default for SignalHandlers {
    fn default() -> Self {
        Self(Box::new(RefCell::new(SignalHandlersInner::default())))
    }
}

impl Deref for SignalHandlers {
    type Target = Box<RefCell<SignalHandlersInner>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignalHandlers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
