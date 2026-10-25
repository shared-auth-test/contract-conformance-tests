//! Server-to-server authorization-code exchange for upstream OAuth2/OIDC providers.
//!
//! This module is intentionally *not* an identity verifier. It turns a consumed,
//! provider/callback/PKCE-bound browser transaction into a bounded opaque token
//! response. A later verifier must authenticate the OIDC ID token or retrieve a
//! provider-specific OAuth2 subject before anything here can become a Shared
//! Auth principal or session.

use std::{collections::BTreeMap, fmt, time::Duration};

use anyhow::{bail, Context, Result};
use futures_util::TryStreamExt;
use serde::Deserialize;

use crate::{
    upstream_federation::{UpstreamProtocol, UpstreamProviderRegistry},
    upstream_oauth_transaction::ConsumedUpstreamOauthTransaction,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_AUTHORIZATION_CODE: usize = 4096;
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_BEARER_BYTES: usize = 16 * 1024;
const MAX_SCOPE_BYTES: usize = 4096;

/// Opaque upstream bearer material. Debug output is always redacted; callers
/// must explicitly cross the secret boundary to present it to a verifier or
/// provider endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct UpstreamBearerSecret(String);

impl UpstreamBearerSecret {
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UpstreamBearerSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UpstreamBearerSecret([REDACTED])")
    }
}

/// Result of a successful upstream token-endpoint exchange. Possessing this
/// value does not authenticate a local principal; cryptographic/subject
/// verification is a separate mandatory boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct UpstreamTokenSet {
    pub access_token: UpstreamBearerSecret,
    pub id_token: Option<UpstreamBearerSecret>,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
}

impl fmt::Debug for UpstreamTokenSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamTokenSet")
            .field("access_token", &self.access_token)
            .field("id_token", &self.id_token)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Deserialize)]
struct RawTokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

/// Exchange one upstream authorization code using only registered provider
/// metadata, env-resolved credentials, and the already-consumed transaction.
///
/// Redirects are disabled because a token endpoint is a credential boundary:
/// client secret, code and PKCE verifier must never be replayed to a different
/// origin chosen by an upstream redirect.
pub async fn exchange_authorization_code(
    registry: &UpstreamProviderRegistry,
    provider_id: &str,
    env: &BTreeMap<String, String>,
    transaction: &ConsumedUpstreamOauthTransaction,
    authorization_code: &str,
) -> Result<UpstreamTokenSet> {
    registry.validate()?;
    let provider = registry
        .by_id(provider_id)
        .ok_or_else(|| anyhow::anyhow!("upstream provider is not registered"))?;
    if transaction.provider_id != provider.id {
        bail!("upstream transaction provider binding mismatch");
    }
    validate_authorization_code(authorization_code)?;
    let (client_id, client_secret) = registry.credentials(provider, env)?;

    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("shared-auth-upstream-oauth/1")
        .build()
        .context("building upstream OAuth token client")?;

    let response = http
        .post(&provider.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", authorization_code),
            ("redirect_uri", transaction.callback_uri.as_str()),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code_verifier", transaction.code_verifier.expose_secret()),
        ])
        .send()
        .await
        .context("upstream OAuth token exchange failed")?;

    if !response.status().is_success() {
        bail!("upstream OAuth token endpoint rejected the exchange");
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_TOKEN_RESPONSE_BYTES as u64)
    {
        bail!("upstream OAuth token response exceeds size limit");
    }

    let body = response
        .bytes_stream()
        .map_err(|_| anyhow::anyhow!("reading upstream OAuth token response failed"))
        .try_fold(Vec::<u8>::new(), |body, chunk| async move {
            if body.len().saturating_add(chunk.len()) > MAX_TOKEN_RESPONSE_BYTES {
                bail!("upstream OAuth token response exceeds size limit");
            }
            Ok([body.as_slice(), chunk.as_ref()].concat())
        })
        .await?;

    parse_token_response(provider.protocol, &body)
}

fn parse_token_response(protocol: UpstreamProtocol, body: &[u8]) -> Result<UpstreamTokenSet> {
    if body.is_empty() || body.len() > MAX_TOKEN_RESPONSE_BYTES {
        bail!("upstream OAuth token response has invalid size");
    }
    let raw: RawTokenResponse =
        serde_json::from_slice(body).context("parsing upstream OAuth token response")?;
    if !raw.token_type.eq_ignore_ascii_case("bearer") {
        bail!("upstream OAuth token response has unsupported token type");
    }
    validate_bearer("access token", &raw.access_token)?;
    if raw
        .scope
        .as_deref()
        .is_some_and(|scope| scope.len() > MAX_SCOPE_BYTES || scope.chars().any(char::is_control))
    {
        bail!("upstream OAuth token response scope has invalid shape");
    }
    let id_token = match raw.id_token {
        Some(token) => {
            validate_bearer("ID token", &token)?;
            Some(UpstreamBearerSecret(token))
        }
        None if protocol == UpstreamProtocol::Oidc => {
            bail!("OIDC token response is missing id_token")
        }
        None => None,
    };

    Ok(UpstreamTokenSet {
        access_token: UpstreamBearerSecret(raw.access_token),
        id_token,
        expires_in: raw.expires_in,
        scope: raw.scope,
    })
}

fn validate_authorization_code(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_AUTHORIZATION_CODE
        || value.chars().any(char::is_control)
    {
        bail!("upstream OAuth authorization code has invalid shape");
    }
    Ok(())
}

fn validate_bearer(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_BEARER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        bail!("upstream OAuth {label} has invalid shape");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_requires_id_token_and_redacts_bearers() {
        let body = br#"{
          "access_token":"access-secret",
          "token_type":"Bearer",
          "expires_in":3600,
          "scope":"openid profile",
          "id_token":"header.payload.signature"
        }"#;
        let tokens = parse_token_response(UpstreamProtocol::Oidc, body).unwrap();
        assert_eq!(tokens.access_token.expose_secret(), "access-secret");
        assert_eq!(
            tokens.id_token.as_ref().map(UpstreamBearerSecret::expose_secret),
            Some("header.payload.signature")
        );
        let debug = format!("{tokens:?}");
        assert!(!debug.contains("access-secret"));
        assert!(!debug.contains("header.payload.signature"));
    }

    #[test]
    fn oidc_without_id_token_fails_closed() {
        let body = br#"{"access_token":"access-secret","token_type":"Bearer"}"#;
        assert!(parse_token_response(UpstreamProtocol::Oidc, body).is_err());
    }

    #[test]
    fn oauth2_can_defer_subject_lookup_without_id_token() {
        let body = br#"{"access_token":"access-secret","token_type":"bearer"}"#;
        let tokens = parse_token_response(UpstreamProtocol::Oauth2, body).unwrap();
        assert!(tokens.id_token.is_none());
    }

    #[test]
    fn rejects_wrong_token_type_or_oversized_secret() {
        let wrong = br#"{"access_token":"access-secret","token_type":"mac"}"#;
        assert!(parse_token_response(UpstreamProtocol::Oauth2, wrong).is_err());

        let oversized = format!(
            "{{\"access_token\":\"{}\",\"token_type\":\"Bearer\"}}",
            "a".repeat(MAX_BEARER_BYTES + 1)
        );
        assert!(parse_token_response(UpstreamProtocol::Oauth2, oversized.as_bytes()).is_err());
    }

    #[test]
    fn authorization_code_is_bounded_without_reflection() {
        assert!(validate_authorization_code("visible-provider-code").is_ok());
        assert!(validate_authorization_code("").is_err());
        assert!(validate_authorization_code("bad\ncode").is_err());
    }
}
