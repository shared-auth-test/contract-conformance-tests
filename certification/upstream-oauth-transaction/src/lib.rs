//! Replay-safe transaction boundary for upstream OAuth/OIDC login ceremonies.
//!
//! Provider metadata lives in `upstream_federation`; this module owns only the
//! ephemeral browser transaction state required before any upstream token
//! exchange is permitted. Upstream bearer tokens never enter this store.
//!
//! Raw browser `state` and OIDC `nonce` values are returned to the caller but
//! are not retained by the store. The store keys transactions by SHA-256(state)
//! and retains only SHA-256(nonce). The PKCE verifier must remain recoverable for
//! the server-to-server token exchange, so it is held in an explicitly redacted
//! wrapper whose `Debug` implementation never exposes its value.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::SysRng, TryRng};
use sha2::{Digest, Sha256};

const DEFAULT_TTL: Duration = Duration::from_secs(600);
const MAX_TRANSACTIONS: usize = 16_384;
const MAX_PROVIDER_ID: usize = 96;
const MAX_CALLBACK_URI: usize = 2048;
const MAX_CONTINUATION: usize = 4096;
const RANDOM_SECRET_LEN: usize = 43;
const PLACEHOLDER_ORIGIN: &str = "https://shared-auth.invalid";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamOauthStart {
    pub provider_id: String,
    pub callback_uri: String,
    pub continuation: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct UpstreamOauthChallenge {
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
}

impl fmt::Debug for UpstreamOauthChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamOauthChallenge")
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("code_challenge", &self.code_challenge)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct UpstreamSecret(String);

impl UpstreamSecret {
    /// Explicitly cross the redaction boundary for the server-to-server token
    /// exchange. Callers must never log or serialize this value.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UpstreamSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UpstreamSecret([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsumedUpstreamOauthTransaction {
    pub provider_id: String,
    pub callback_uri: String,
    pub continuation: String,
    nonce_hash: [u8; 32],
    pub code_verifier: UpstreamSecret,
}

impl ConsumedUpstreamOauthTransaction {
    /// Compare a provider-verified OIDC nonce without retaining the raw nonce in
    /// the transaction store or exposing the expected value to diagnostics.
    #[must_use]
    pub fn oidc_nonce_matches(&self, presented: &str) -> bool {
        valid_random_secret(presented) && constant_time_eq(&self.nonce_hash, &digest(presented))
    }
}

impl fmt::Debug for ConsumedUpstreamOauthTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumedUpstreamOauthTransaction")
            .field("provider_id", &self.provider_id)
            .field("callback_uri", &self.callback_uri)
            .field("continuation", &self.continuation)
            .field("nonce_hash", &"[REDACTED]")
            .field("code_verifier", &self.code_verifier)
            .finish()
    }
}

#[derive(Clone)]
pub struct UpstreamOauthTransactionStore {
    // Browser-visible state is never retained verbatim. Its digest is enough
    // for one-time lookup and keeps raw correlation material out of snapshots.
    inner: Arc<Mutex<BTreeMap<[u8; 32], Entry>>>,
    ttl: Duration,
}

struct Entry {
    provider_id: String,
    callback_uri: String,
    continuation: String,
    nonce_hash: [u8; 32],
    code_verifier: UpstreamSecret,
    expires_at: SystemTime,
}

impl Default for UpstreamOauthTransactionStore {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

impl UpstreamOauthTransactionStore {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
            ttl,
        }
    }

    pub fn begin(&self, start: UpstreamOauthStart) -> Result<UpstreamOauthChallenge> {
        validate_start(&start)?;
        if self.ttl.is_zero() || self.ttl > Duration::from_secs(3600) {
            bail!("upstream OAuth transaction TTL must be between 1s and 1h");
        }

        let state = random_secret()?;
        let nonce = random_secret()?;
        let code_verifier = random_secret()?;
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let now = SystemTime::now();
        let expires_at = now
            .checked_add(self.ttl)
            .ok_or_else(|| anyhow::anyhow!("upstream OAuth transaction expiry overflow"))?;

        let mut entries = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("upstream OAuth transaction store poisoned"))?;
        entries.retain(|_, entry| entry.expires_at > now);
        if entries.len() >= MAX_TRANSACTIONS {
            bail!("upstream OAuth transaction store is at capacity");
        }
        entries.insert(
            digest(&state),
            Entry {
                provider_id: start.provider_id,
                callback_uri: start.callback_uri,
                continuation: start.continuation,
                nonce_hash: digest(&nonce),
                code_verifier: UpstreamSecret(code_verifier),
                expires_at,
            },
        );

        Ok(UpstreamOauthChallenge {
            state,
            nonce,
            code_challenge,
        })
    }

    /// Consume exactly one transaction. State replay, provider switching,
    /// callback substitution, expiry, and unknown state all fail closed. A
    /// wrong state cannot burn a valid transaction because lookup happens by
    /// the supplied state's digest. Once a state matches, provider/callback
    /// substitution removes and burns the transaction before returning an error.
    pub fn consume(
        &self,
        state: &str,
        provider_id: &str,
        callback_uri: &str,
    ) -> Result<ConsumedUpstreamOauthTransaction> {
        if !valid_random_secret(state) {
            bail!("upstream OAuth state has invalid shape");
        }
        let now = SystemTime::now();
        let mut entries = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("upstream OAuth transaction store poisoned"))?;
        entries.retain(|_, entry| entry.expires_at > now);
        let entry = entries.remove(&digest(state)).ok_or_else(|| {
            anyhow::anyhow!("upstream OAuth transaction is missing or already consumed")
        })?;

        if entry.expires_at <= now {
            bail!("upstream OAuth transaction expired");
        }
        if entry.provider_id != provider_id || entry.callback_uri != callback_uri {
            bail!("upstream OAuth callback binding mismatch");
        }

        Ok(ConsumedUpstreamOauthTransaction {
            provider_id: entry.provider_id,
            callback_uri: entry.callback_uri,
            continuation: entry.continuation,
            nonce_hash: entry.nonce_hash,
            code_verifier: entry.code_verifier,
        })
    }
}

fn validate_start(start: &UpstreamOauthStart) -> Result<()> {
    if start.provider_id.is_empty()
        || start.provider_id.len() > MAX_PROVIDER_ID
        || !start
            .provider_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("upstream OAuth provider id has invalid shape");
    }
    validate_callback_uri(&start.callback_uri)?;
    validate_continuation(&start.continuation)?;
    Ok(())
}

fn validate_callback_uri(value: &str) -> Result<()> {
    validate_bound("callback URI", value, MAX_CALLBACK_URI)?;
    let url = reqwest::Url::parse(value)
        .map_err(|_| anyhow::anyhow!("upstream OAuth callback URI is invalid"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!(
            "upstream OAuth callback URI must be credential-free HTTPS without query or fragment"
        );
    }
    Ok(())
}

fn validate_continuation(value: &str) -> Result<()> {
    validate_bound("continuation", value, MAX_CONTINUATION)?;
    if !value.starts_with('/') || value.starts_with("//") {
        bail!("upstream OAuth continuation must be a same-origin absolute path");
    }
    let url = reqwest::Url::parse(&format!("{PLACEHOLDER_ORIGIN}{value}"))
        .map_err(|_| anyhow::anyhow!("upstream OAuth continuation is invalid"))?;
    if url.path() != "/oauth/authorize" || url.fragment().is_some() {
        bail!("upstream OAuth continuation must resume /oauth/authorize");
    }
    Ok(())
}

fn validate_bound(label: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        bail!("upstream OAuth {label} has invalid shape");
    }
    Ok(())
}

fn valid_random_secret(value: &str) -> bool {
    value.len() == RANDOM_SECRET_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn random_secret() -> Result<String> {
    let mut bytes = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| anyhow::anyhow!("secure random generation failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> UpstreamOauthStart {
        UpstreamOauthStart {
            provider_id: "linkedin".into(),
            callback_uri: "https://auth.example.test/auth/upstream/linkedin/callback".into(),
            continuation: "/oauth/authorize?client_id=child&state=downstream".into(),
        }
    }

    #[test]
    fn transaction_is_bound_redacted_and_one_time() {
        let store = UpstreamOauthTransactionStore::default();
        let challenge = store.begin(start()).unwrap();
        assert_ne!(challenge.state, challenge.nonce);
        assert!(!challenge.code_challenge.is_empty());
        let debug = format!("{challenge:?}");
        assert!(!debug.contains(&challenge.state));
        assert!(!debug.contains(&challenge.nonce));

        let consumed = store
            .consume(
                &challenge.state,
                "linkedin",
                "https://auth.example.test/auth/upstream/linkedin/callback",
            )
            .unwrap();
        assert_eq!(consumed.provider_id, "linkedin");
        assert!(consumed.oidc_nonce_matches(&challenge.nonce));
        assert!(!consumed.oidc_nonce_matches("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!consumed.code_verifier.expose_secret().is_empty());
        let consumed_debug = format!("{consumed:?}");
        assert!(!consumed_debug.contains(consumed.code_verifier.expose_secret()));
        assert!(!consumed_debug.contains(&challenge.nonce));
        assert!(store
            .consume(
                &challenge.state,
                "linkedin",
                "https://auth.example.test/auth/upstream/linkedin/callback",
            )
            .is_err());
    }

    #[test]
    fn raw_state_is_not_retained_as_store_key() {
        let store = UpstreamOauthTransactionStore::default();
        let challenge = store.begin(start()).unwrap();
        let entries = store.inner.lock().unwrap();
        assert!(entries.contains_key(&digest(&challenge.state)));
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn wrong_state_does_not_burn_valid_transaction() {
        let store = UpstreamOauthTransactionStore::default();
        let challenge = store.begin(start()).unwrap();
        let wrong_state = random_secret().unwrap();
        assert_ne!(wrong_state, challenge.state);
        assert!(store
            .consume(
                &wrong_state,
                "linkedin",
                "https://auth.example.test/auth/upstream/linkedin/callback",
            )
            .is_err());
        assert!(store
            .consume(
                &challenge.state,
                "linkedin",
                "https://auth.example.test/auth/upstream/linkedin/callback",
            )
            .is_ok());
    }

    #[test]
    fn provider_or_callback_substitution_consumes_and_fails_closed() {
        let store = UpstreamOauthTransactionStore::default();
        let challenge = store.begin(start()).unwrap();
        assert!(store
            .consume(
                &challenge.state,
                "facebook",
                "https://auth.example.test/auth/upstream/linkedin/callback",
            )
            .is_err());
        assert!(store
            .consume(
                &challenge.state,
                "linkedin",
                "https://auth.example.test/auth/upstream/linkedin/callback",
            )
            .is_err());
    }

    #[test]
    fn callback_and_continuation_are_fail_closed() {
        let store = UpstreamOauthTransactionStore::default();
        let mut unsafe_callback = start();
        unsafe_callback.callback_uri = "https://user:secret@auth.example.test/cb".into();
        assert!(store.begin(unsafe_callback).is_err());

        let mut off_origin = start();
        off_origin.continuation = "https://evil.example/steal".into();
        assert!(store.begin(off_origin).is_err());

        let mut wrong_path = start();
        wrong_path.continuation = "/auth/browser/sign-in".into();
        assert!(store.begin(wrong_path).is_err());
    }

    #[test]
    fn zero_ttl_is_rejected() {
        let store = UpstreamOauthTransactionStore::new(Duration::ZERO);
        assert!(store.begin(start()).is_err());
    }
}
