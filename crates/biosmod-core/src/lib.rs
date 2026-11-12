//! Biosmod Engine core: firmware inspection, catalog validation, guarded
//! patch planning and output verification.
//!
//! The core performs no filesystem, network or terminal I/O. Callers supply
//! bytes and a [`catalog::FileSource`]; every function returns typed results.

pub mod analysis;
pub mod breadcrumbs;
pub mod catalog;
pub mod codec;
pub mod error;
pub mod firmware;
pub mod ifr;
pub mod json;
pub mod legacy;
pub mod nvram;
pub mod patch;
pub mod plan;
pub mod schema;
pub mod synthetic;
pub mod util;
pub mod validation;

pub use error::{Code, Error, Result};

/// Engine version, e.g. `"0.1.0"`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
