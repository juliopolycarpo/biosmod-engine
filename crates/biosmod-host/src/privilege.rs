//! Who is running the command.

use biosmod_core::{Code, Error, Result};

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

/// Refuse unless the effective user is root, naming the user that was found.
///
/// Example: `require_root(&ProcessPrivilege, "diag superio read")?` is the first line of a
/// command that reads ports.
pub fn require_root(privilege: &dyn Privilege, command: &str) -> Result<()> {
    if privilege.is_root() {
        return Ok(());
    }
    Err(Error::new(
        Code::HostRefused,
        format!(
            "{command}: expected effective user root | received {} (the host files and ports it reads are root-only; run as root)",
            privilege
                .effective_user()
                .map_or("none".to_string(), |uid| format!("uid {uid}"))
        ),
    ))
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

    #[test]
    fn require_root_names_the_command_and_the_user_found() {
        assert!(require_root(&FakePrivilege::root(), "diag x").is_ok());
        for (privilege, received) in [
            (FakePrivilege::user(1000), "uid 1000"),
            (FakePrivilege::unknown(), "none"),
        ] {
            let error = require_root(&privilege, "diag x").unwrap_err();
            assert_eq!(error.code, Code::HostRefused);
            assert!(
                error.message.starts_with(&format!(
                    "diag x: expected effective user root | received {received}"
                )),
                "{error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_process_reports_a_user_id() {
        assert!(ProcessPrivilege.effective_user().is_some());
    }
}
