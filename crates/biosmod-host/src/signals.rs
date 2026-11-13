//! Deferring termination signals while a chip is in an unusual state.
//!
//! Between the Super I/O entry key and the exit key (and while a hardware-monitor
//! bank other than the original is selected) an interrupted process would leave the
//! chip in configuration mode or a kernel hwmon driver reading the wrong bank. A
//! [`SignalBlock`] holds `SIGINT`, `SIGTERM` and `SIGHUP` pending for that window; they
//! are delivered when it drops, after the selectors are back.
//!
//! Limits: `SIGKILL` and `SIGSTOP` cannot be blocked, and a release build aborts on
//! panic without running destructors. The mask is per thread, which is the whole
//! process for this single-threaded command. Not unix: no-op.

/// Signals a terminal or a service manager sends to ask a process to stop.
#[cfg(unix)]
const DEFERRED: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// Holds the deferred signals pending until dropped, then restores the previous mask.
///
/// Example: `let _held = SignalBlock::new();` at the top of a function that must not be
/// interrupted halfway.
#[cfg(unix)]
pub struct SignalBlock {
    previous: libc::sigset_t,
}

#[cfg(unix)]
impl SignalBlock {
    pub fn new() -> SignalBlock {
        // SAFETY: the sets are initialised by sigemptyset before use, and
        // pthread_sigmask only reads `set` and writes `previous`.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for signal in DEFERRED {
                libc::sigaddset(&mut set, signal);
            }
            let mut previous: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut previous);
            SignalBlock { previous }
        }
    }
}

#[cfg(unix)]
impl Default for SignalBlock {
    fn default() -> SignalBlock {
        SignalBlock::new()
    }
}

#[cfg(unix)]
impl Drop for SignalBlock {
    fn drop(&mut self) {
        // SAFETY: `previous` came from pthread_sigmask.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

/// Whether `signal` is blocked on the calling thread.
///
/// Example: inside a [`SignalBlock`], `is_blocked(libc::SIGINT)` is `true`.
#[cfg(unix)]
pub fn is_blocked(signal: libc::c_int) -> bool {
    // SAFETY: with a null `set`, pthread_sigmask only writes the current mask.
    unsafe {
        let mut current: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current);
        libc::sigismember(&current, signal) == 1
    }
}

/// No signals to defer on this platform.
#[cfg(not(unix))]
pub struct SignalBlock;

#[cfg(not(unix))]
impl SignalBlock {
    pub fn new() -> SignalBlock {
        SignalBlock
    }
}

#[cfg(not(unix))]
impl Default for SignalBlock {
    fn default() -> SignalBlock {
        SignalBlock::new()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_stop_signals_are_blocked_inside_the_guard_and_restored_after() {
        let before: Vec<bool> = DEFERRED.iter().map(|s| is_blocked(*s)).collect();
        assert_eq!(
            before,
            [false, false, false],
            "(test thread): expected unblocked at start"
        );
        {
            let _held = SignalBlock::new();
            for signal in DEFERRED {
                assert!(
                    is_blocked(signal),
                    "(signal {signal}): expected blocked inside the guard"
                );
            }
            assert!(!is_blocked(libc::SIGUSR1), "(SIGUSR1): expected untouched");
        }
        let after: Vec<bool> = DEFERRED.iter().map(|s| is_blocked(*s)).collect();
        assert_eq!(after, before);
    }

    #[test]
    fn nested_guards_leave_the_outer_block_in_place() {
        let _outer = SignalBlock::new();
        drop(SignalBlock::new());
        assert!(
            is_blocked(libc::SIGTERM),
            "(SIGTERM): expected still blocked by the outer guard"
        );
    }
}
