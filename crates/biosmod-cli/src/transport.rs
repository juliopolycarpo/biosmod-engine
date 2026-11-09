//! Bounded HTTPS downloads behind a project-owned interface.
//!
//! Only `https://` URLs are fetched, bodies are capped at the caller's limit
//! and requests time out. Catalog transports follow redirects only within the
//! same origin; artifact transports, whose downloads are checked against
//! pinned digests, follow HTTPS redirects to any host (release assets are
//! served from a CDN). Both stop after three redirects.

use biosmod_core::{Code, Error, Result};
use std::time::Duration;

/// Fetch a URL's body, failing beyond `limit` bytes.
pub trait Transport {
    fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>>;

    /// Stream a body into `sink`, returning its length. The default buffers through [`Transport::get`].
    fn download(&self, url: &str, sink: &mut dyn std::io::Write, limit: u64) -> Result<u64> {
        let bytes = self.get(url, limit)?;
        sink.write_all(&bytes)
            .map_err(|e| Error::new(Code::Io, format!("{url}: writing download: {e}")))?;
        Ok(bytes.len() as u64)
    }
}

/// The scheme-host-port origin of an HTTPS URL, or an error for anything else.
pub fn origin(url: &str) -> Result<&str> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        Error::new(
            Code::SourceUntrusted,
            format!("{url}: expected an https:// URL (plain HTTP and other schemes are refused)"),
        )
    })?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..end];
    if host.is_empty() || host.contains('@') {
        return Err(Error::new(
            Code::SourceUntrusted,
            format!("{url}: expected https://host/path without credentials"),
        ));
    }
    Ok(&url[..8 + end])
}

/// Which redirects a transport follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redirects {
    /// Same scheme, host and port only (catalog sources).
    SameOrigin,
    /// Any HTTPS URL; only for downloads verified against a pinned digest.
    AnyHttps,
}

/// Resolve a redirect target relative to `base` and apply `policy`.
fn redirect_target(base: &str, location: &str, policy: Redirects) -> Result<String> {
    let target = if location.starts_with('/') && !location.starts_with("//") {
        format!("{}{location}", origin(base)?)
    } else {
        location.to_string()
    };
    let target_origin = origin(&target)?;
    if policy == Redirects::SameOrigin && target_origin != origin(base)? {
        return Err(Error::new(
            Code::SourceUntrusted,
            format!("{base}: redirect to another origin ({target}) refused"),
        ));
    }
    Ok(target)
}

/// The production transport (rustls with bundled web PKI roots).
pub struct Https {
    agent: ureq::Agent,
    redirects: Redirects,
}

impl Https {
    /// For catalog sources: same-origin redirects, two-minute requests.
    pub fn catalogs() -> Https {
        Https::new(Redirects::SameOrigin, Duration::from_secs(120))
    }

    /// For digest-pinned artifacts such as tool archives: any HTTPS redirect, one-hour requests.
    pub fn pinned_artifacts() -> Https {
        Https::new(Redirects::AnyHttps, Duration::from_secs(3600))
    }

    fn new(redirects: Redirects, timeout: Duration) -> Https {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .timeout_connect(Some(Duration::from_secs(20)))
            .user_agent(concat!("biosmod-engine/", env!("CARGO_PKG_VERSION")))
            .build();
        Https {
            agent: config.into(),
            redirects,
        }
    }
}

impl Https {
    /// Follow redirects allowed by the policy and return a 200 response.
    fn response(&self, url: &str) -> Result<(String, ureq::http::Response<ureq::Body>)> {
        let mut current = url.to_string();
        origin(&current)?;
        for _ in 0..=3 {
            let response = self
                .agent
                .get(&current)
                .call()
                .map_err(|e| Error::new(Code::SourceUnavailable, format!("{current}: {e}")))?;
            let status = response.status().as_u16();
            if (300..400).contains(&status) {
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                current = redirect_target(&current, &location, self.redirects)?;
                continue;
            }
            if status != 200 {
                return Err(Error::new(
                    Code::SourceUnavailable,
                    format!("{current}: HTTP status {status} | expected 200"),
                ));
            }
            return Ok((current, response));
        }
        Err(Error::new(
            Code::SourceUnavailable,
            format!("{url}: more than 3 redirects"),
        ))
    }
}

impl Transport for Https {
    fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>> {
        let (current, mut response) = self.response(url)?;
        response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|e| {
                Error::new(
                    Code::SourceUpdateRejected,
                    format!("{current}: {e} (limit {limit} bytes)"),
                )
            })
    }

    fn download(&self, url: &str, sink: &mut dyn std::io::Write, limit: u64) -> Result<u64> {
        let (current, mut response) = self.response(url)?;
        let mut reader = response.body_mut().with_config().limit(limit).reader();
        std::io::copy(&mut reader, sink).map_err(|e| {
            Error::new(
                Code::SourceUnavailable,
                format!("{current}: {e} (limit {limit} bytes)"),
            )
        })
    }
}

/// A transport that refuses every request (used with `--offline`).
pub struct Offline;

impl Transport for Offline {
    fn get(&self, url: &str, _limit: u64) -> Result<Vec<u8>> {
        Err(Error::new(
            Code::SourceUnavailable,
            format!("{url}: network access is disabled by --offline"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_origins_are_accepted() {
        assert_eq!(
            origin("https://example.org/a/catalog.json").unwrap(),
            "https://example.org"
        );
        assert_eq!(
            origin("https://example.org:8443").unwrap(),
            "https://example.org:8443"
        );
        for bad in [
            "http://example.org/x",
            "file:///etc/passwd",
            "https://user@host/x",
            "https:///x",
        ] {
            assert_eq!(
                origin(bad).unwrap_err().code,
                Code::SourceUntrusted,
                "{bad}"
            );
        }
    }

    #[test]
    fn redirects_stay_on_the_same_origin() {
        let base = "https://example.org/cat/catalog.json";
        assert_eq!(
            redirect_target(base, "/v2/catalog.json", Redirects::SameOrigin).unwrap(),
            "https://example.org/v2/catalog.json"
        );
        assert!(redirect_target(base, "https://evil.example/x", Redirects::SameOrigin).is_err());
        assert!(redirect_target(base, "http://example.org/x", Redirects::SameOrigin).is_err());
        assert!(redirect_target(base, "//evil.example/x", Redirects::SameOrigin).is_err());
        // Pinned artifacts may move to a CDN, but never off HTTPS.
        let cdn = "https://release-assets.example.net/a?sig=1";
        assert_eq!(
            redirect_target(base, cdn, Redirects::AnyHttps).unwrap(),
            cdn
        );
        assert!(redirect_target(base, "http://cdn.example/x", Redirects::AnyHttps).is_err());
    }
}
