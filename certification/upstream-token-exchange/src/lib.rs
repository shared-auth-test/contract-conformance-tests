use std::collections::BTreeMap;

pub mod upstream_federation {
    use std::collections::BTreeMap;
    use anyhow::Result;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum UpstreamProtocol { Oauth2, Oidc }

    pub struct UpstreamProvider {
        pub id: String,
        pub token_endpoint: String,
        pub protocol: UpstreamProtocol,
    }

    pub struct UpstreamProviderRegistry {
        provider: UpstreamProvider,
        client_id: String,
        client_secret: String,
    }

    impl UpstreamProviderRegistry {
        #[must_use]
        pub fn fixture(protocol: UpstreamProtocol) -> Self {
            Self {
                provider: UpstreamProvider {
                    id: "fixture".to_owned(),
                    token_endpoint: "https://provider.example.test/oauth/token".to_owned(),
                    protocol,
                },
                client_id: "client".to_owned(),
                client_secret: "secret".to_owned(),
            }
        }

        pub fn validate(&self) -> Result<()> { Ok(()) }

        #[must_use]
        pub fn by_id(&self, provider_id: &str) -> Option<&UpstreamProvider> {
            (provider_id == self.provider.id).then_some(&self.provider)
        }

        pub fn credentials<'a>(
            &'a self,
            _provider: &'a UpstreamProvider,
            _env: &'a BTreeMap<String, String>,
        ) -> Result<(&'a str, &'a str)> {
            Ok((&self.client_id, &self.client_secret))
        }
    }
}

pub mod upstream_oauth_transaction {
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct UpstreamSecret(pub String);

    impl UpstreamSecret {
        #[must_use]
        pub fn expose_secret(&self) -> &str { &self.0 }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ConsumedUpstreamOauthTransaction {
        pub provider_id: String,
        pub callback_uri: String,
        pub continuation: String,
        pub code_verifier: UpstreamSecret,
    }
}

pub mod upstream_token_exchange;

#[cfg(test)]
mod harness_tests {
    use super::*;

    #[test]
    fn dependency_stubs_are_minimal_and_deterministic() {
        let registry = upstream_federation::UpstreamProviderRegistry::fixture(
            upstream_federation::UpstreamProtocol::Oidc,
        );
        assert!(registry.by_id("fixture").is_some());
        let env = BTreeMap::new();
        let provider = registry.by_id("fixture").unwrap();
        assert_eq!(registry.credentials(provider, &env).unwrap(), ("client", "secret"));
    }
}
