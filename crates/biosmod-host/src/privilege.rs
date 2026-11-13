//! Who is running the command.

/// The effective user of the process.
pub trait Privilege {
    /// The effective user id, or `None` on platforms without one.
    fn effective_user(&self) -> Option<u32>;

    /// Whether the effective user is root.
    ///
    /// Example: `FakePrivilege::root().is_root()` is `true`.
    fn is_root(&self) -> bool {
        self.effective_user() == Some(0)
    }
}

/// The running process.
pub struct ProcessPrivilege;

#[cfg(unix)]
impl Privilege for ProcessPrivilege {
    fn effective_user(&self) -> Option<u32> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        Some(unsafe { libc::geteuid() })
    }
}

#[cfg(not(unix))]
impl Privilege for ProcessPrivilege {
    fn effective_user(&self) -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::FakePrivilege;

    #[test]
    fn root_is_uid_zero_only() {
        assert!(FakePrivilege::root().is_root());
        assert!(!FakePrivilege::user(1000).is_root());
        assert!(!FakePrivilege::unknown().is_root());
    }

    #[cfg(unix)]
    #[test]
    fn the_process_reports_a_user_id() {
        assert!(ProcessPrivilege.effective_user().is_some());
    }
}
