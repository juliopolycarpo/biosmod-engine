//! Typed errors with stable machine codes.
//!
//! Human wording may change between releases; [`Code`] identifiers do not.

use serde::Serialize;
use std::fmt;

/// Stable machine-readable error identifiers shared by every command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Code {
    Usage,
    Io,
    CatalogInvalid,
    SourceUntrusted,
    SourceUnavailable,
    SourceUpdateRejected,
    FormatInvalid,
    FormatUnsupported,
    TargetNotFound,
    TargetAmbiguous,
    SelectionInvalid,
    PatchSourceMismatch,
    PatchConflict,
    PatchStateUnsafe,
    PackingRefused,
    AssertionRequired,
    PlanInvalid,
    PlanInputChanged,
    OutputExists,
    OutputVerificationFailed,
    VerificationIncomplete,
    PublishIncomplete,
    ToolUnavailable,
    ToolSetupFailed,
    ToolFailed,
    PlatformUnsupported,
    FlashRefused,
    FlashFailed,
    HostRefused,
    Internal,
}

impl Code {
    /// Every code, in documentation order.
    pub const ALL: [Code; 30] = [
        Code::Usage,
        Code::Io,
        Code::CatalogInvalid,
        Code::SourceUntrusted,
        Code::SourceUnavailable,
        Code::SourceUpdateRejected,
        Code::FormatInvalid,
        Code::FormatUnsupported,
        Code::TargetNotFound,
        Code::TargetAmbiguous,
        Code::SelectionInvalid,
        Code::PatchSourceMismatch,
        Code::PatchConflict,
        Code::PatchStateUnsafe,
        Code::PackingRefused,
        Code::AssertionRequired,
        Code::PlanInvalid,
        Code::PlanInputChanged,
        Code::OutputExists,
        Code::OutputVerificationFailed,
        Code::VerificationIncomplete,
        Code::PublishIncomplete,
        Code::ToolUnavailable,
        Code::ToolSetupFailed,
        Code::ToolFailed,
        Code::PlatformUnsupported,
        Code::FlashRefused,
        Code::FlashFailed,
        Code::HostRefused,
        Code::Internal,
    ];

    /// The serialized identifier, e.g. `Code::PatchConflict.as_str() == "PATCH_CONFLICT"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Usage => "USAGE",
            Code::Io => "IO",
            Code::CatalogInvalid => "CATALOG_INVALID",
            Code::SourceUntrusted => "SOURCE_UNTRUSTED",
            Code::SourceUnavailable => "SOURCE_UNAVAILABLE",
            Code::SourceUpdateRejected => "SOURCE_UPDATE_REJECTED",
            Code::FormatInvalid => "FORMAT_INVALID",
            Code::FormatUnsupported => "FORMAT_UNSUPPORTED",
            Code::TargetNotFound => "TARGET_NOT_FOUND",
            Code::TargetAmbiguous => "TARGET_AMBIGUOUS",
            Code::SelectionInvalid => "SELECTION_INVALID",
            Code::PatchSourceMismatch => "PATCH_SOURCE_MISMATCH",
            Code::PatchConflict => "PATCH_CONFLICT",
            Code::PatchStateUnsafe => "PATCH_STATE_UNSAFE",
            Code::PackingRefused => "PACKING_REFUSED",
            Code::AssertionRequired => "ASSERTION_REQUIRED",
            Code::PlanInvalid => "PLAN_INVALID",
            Code::PlanInputChanged => "PLAN_INPUT_CHANGED",
            Code::OutputExists => "OUTPUT_EXISTS",
            Code::OutputVerificationFailed => "OUTPUT_VERIFICATION_FAILED",
            Code::VerificationIncomplete => "VERIFICATION_INCOMPLETE",
            Code::PublishIncomplete => "PUBLISH_INCOMPLETE",
            Code::ToolUnavailable => "TOOL_UNAVAILABLE",
            Code::ToolSetupFailed => "TOOL_SETUP_FAILED",
            Code::ToolFailed => "TOOL_FAILED",
            Code::PlatformUnsupported => "PLATFORM_UNSUPPORTED",
            Code::FlashRefused => "FLASH_REFUSED",
            Code::FlashFailed => "FLASH_FAILED",
            Code::HostRefused => "HOST_REFUSED",
            Code::Internal => "INTERNAL",
        }
    }

    /// One-line meaning, published through `bme capabilities`.
    pub fn meaning(self) -> &'static str {
        match self {
            Code::Usage => "invalid command-line arguments",
            Code::Io => "a file or directory could not be read or written",
            Code::CatalogInvalid => "a catalog, board profile or patch record failed validation",
            Code::SourceUntrusted => "a catalog source is not trusted by local policy",
            Code::SourceUnavailable => {
                "a source or validated snapshot is not available (offline miss)"
            }
            Code::SourceUpdateRejected => {
                "a catalog update failed verification; the previous snapshot is kept"
            }
            Code::FormatInvalid => "the firmware image is malformed or a checksum is wrong",
            Code::FormatUnsupported => {
                "the firmware uses a layout or encoding outside the supported subset"
            }
            Code::TargetNotFound => "a requested component, patch, board or source does not exist",
            Code::TargetAmbiguous => "a selector matched more than one candidate",
            Code::SelectionInvalid => "the patch selection is not allowed as requested",
            Code::PatchSourceMismatch => {
                "the image does not contain the exact original the patch was made for"
            }
            Code::PatchConflict => "selected or present patches edit the same bytes",
            Code::PatchStateUnsafe => "a component is partially patched or in an unfamiliar state",
            Code::PackingRefused => "the change cannot be packed without moving fixed-address code",
            Code::AssertionRequired => {
                "a hardware fact must be asserted explicitly before planning"
            }
            Code::PlanInvalid => "a plan file is malformed or incompatible with this engine",
            Code::PlanInputChanged => {
                "an input, record or snapshot changed since the plan was made"
            }
            Code::OutputExists => "the output or its manifest exists or aliases an input",
            Code::OutputVerificationFailed => {
                "the rebuilt image failed re-parsing or byte verification"
            }
            Code::VerificationIncomplete => {
                "verification skipped required checks; inspect details and retry"
            }
            Code::PublishIncomplete => {
                "publication stopped part-way; recoverable artifacts are reported"
            }
            Code::ToolUnavailable => "an external analysis tool is missing or incompatible",
            Code::ToolSetupFailed => {
                "tool installation failed; the previous installation is unchanged"
            }
            Code::ToolFailed => "an external tool ran but failed or timed out",
            Code::PlatformUnsupported => "the operation is not implemented on this platform",
            Code::FlashRefused => "a flash chip safety check failed; nothing was written",
            Code::FlashFailed => {
                "a flash chip write or its read-back failed; the chip may hold a partial image"
            }
            Code::HostRefused => {
                "a host diagnostic refused to run: the user, chip, board or request is outside what its safety rules cover; nothing was changed"
            }
            Code::Internal => "an internal invariant failed; please report it",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error with a stable code, a human message and optional structured details.
#[derive(Debug, Clone)]
pub struct Error {
    pub code: Code,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl Error {
    /// Create an error, e.g. `Error::new(Code::TargetNotFound, "patch B99: not in catalog")`.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Error {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Attach structured details for machine consumers.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Prefix the message with context, keeping the code.
    pub fn context(mut self, prefix: impl fmt::Display) -> Self {
        self.message = format!("{prefix}: {}", self.message);
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for Error {}

/// Result alias used across the core.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Return early with an error: `bail!(Code::FormatInvalid, "size {:#x}", n)`.
#[macro_export]
macro_rules! bail {
    ($code:expr, $($arg:tt)*) => {
        return Err($crate::error::Error::new($code, format!($($arg)*)))
    };
}

/// Return an error unless the condition holds.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $code:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::bail!($code, $($arg)*);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_unique_identifier_and_a_meaning() {
        let mut seen = std::collections::BTreeSet::new();
        for code in Code::ALL {
            assert!(
                seen.insert(code.as_str()),
                "(code identifiers): expected unique | received {} twice",
                code.as_str()
            );
            assert!(!code.meaning().is_empty(), "{code}: expected a meaning");
        }
        assert_eq!(Code::HostRefused.as_str(), "HOST_REFUSED");
    }
}
