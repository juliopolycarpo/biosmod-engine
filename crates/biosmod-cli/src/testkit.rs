//! Named fakes for CLI unit tests: an in-memory HTTPS transport and a minisign signer.

use crate::config::Paths;
use crate::transport::Transport;
use base64::Engine;
use biosmod_core::{Code, Error, Result};
use blake2::Digest;
use ed25519_dalek::{Signer, SigningKey};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// Serves registered URLs; can fail after a number of requests to simulate interruption.
#[derive(Default)]
pub struct FakeTransport {
    pub files: RefCell<BTreeMap<String, Vec<u8>>>,
    pub fail_after: RefCell<Option<usize>>,
    pub requests: RefCell<Vec<String>>,
}

impl FakeTransport {
    pub fn put(&self, url: &str, bytes: &[u8]) {
        self.files
            .borrow_mut()
            .insert(url.to_string(), bytes.to_vec());
    }
}

impl Transport for FakeTransport {
    fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>> {
        crate::transport::origin(url)?;
        self.requests.borrow_mut().push(url.to_string());
        if let Some(n) = *self.fail_after.borrow()
            && self.requests.borrow().len() > n
        {
            return Err(Error::new(
                Code::SourceUnavailable,
                format!("{url}: simulated connection reset"),
            ));
        }
        let bytes = self.files.borrow().get(url).cloned().ok_or_else(|| {
            Error::new(
                Code::SourceUnavailable,
                format!("{url}: HTTP status 404 | expected 200"),
            )
        })?;
        if bytes.len() as u64 > limit {
            return Err(Error::new(
                Code::SourceUpdateRejected,
                format!("{url}: body exceeds limit {limit}"),
            ));
        }
        Ok(bytes)
    }
}

/// A deterministic minisign key pair.
pub struct Signer25519 {
    key: SigningKey,
    id: [u8; 8],
}

impl Signer25519 {
    pub fn new(seed: u8) -> Signer25519 {
        Signer25519 {
            key: SigningKey::from_bytes(&[seed; 32]),
            id: [seed, 1, 2, 3, 4, 5, 6, 7],
        }
    }

    /// The public key in minisign base64 form.
    pub fn public(&self) -> String {
        let mut raw = b"Ed".to_vec();
        raw.extend_from_slice(&self.id);
        raw.extend_from_slice(self.key.verifying_key().as_bytes());
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    /// A prehashed (`ED`) minisign signature file for `data`.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let hash = blake2::Blake2b512::digest(data);
        let signature = self.key.sign(&hash).to_bytes();
        let mut raw = b"ED".to_vec();
        raw.extend_from_slice(&self.id);
        raw.extend_from_slice(&signature);
        let trusted = "timestamp:0\tfile:catalog.json";
        let mut global_input = signature.to_vec();
        global_input.extend_from_slice(trusted.as_bytes());
        let global = self.key.sign(&global_input).to_bytes();
        format!(
            "untrusted comment: test\n{}\ntrusted comment: {trusted}\n{}\n",
            b64.encode(raw),
            b64.encode(global)
        )
        .into_bytes()
    }
}

/// Per-test directories.
pub fn temp_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths {
        config: dir.path().join("config"),
        cache: dir.path().join("cache"),
        data: dir.path().join("data"),
    };
    (dir, paths)
}
