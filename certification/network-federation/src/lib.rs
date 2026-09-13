//! Exact-source, credential-free certification for Shared Auth network federation.
//!
//! The snapshots in this crate are pinned by source-lock receipts to the exact
//! server and interface PR heads under review. These tests intentionally avoid
//! production endpoints, credentials, cookies, and provider data.

#[cfg(test)]
use std::collections::BTreeMap;

#[cfg(test)]
const SERVER_SQL: &str = include_str!("../snapshots/network-federation.sql");
#[cfg(test)]
const INTERFACES_TSP: &str = include_str!("../snapshots/network-federation.tsp");
#[cfg(test)]
const SERVER_LOCK: &str = include_str!("../server-source-lock.json");
#[cfg(test)]
const INTERFACES_LOCK: &str = include_str!("../interfaces-source-lock.json");

#[cfg(test)]
#[derive(Default)]
struct PairwiseRegistry {
    next: usize,
    rows: BTreeMap<(String, String), String>,
}

#[cfg(test)]
impl PairwiseRegistry {
    fn resolve(&mut self, sector_id: &str, principal_id: &str) -> String {
        let key = (sector_id.to_owned(), principal_id.to_owned());
        if let Some(subject) = self.rows.get(&key) {
            return subject.clone();
        }
        self.next += 1;
        let subject = format!("opaque_pairwise_subject_{:08}", self.next);
        self.rows.insert(key, subject.clone());
        subject
    }
}

#[cfg(test)]
fn model_body<'a>(source: &'a str, model: &str) -> &'a str {
    let marker = format!("model {model} {{");
    let start = source.find(&marker).expect("model must exist") + marker.len();
    let tail = &source[start..];
    let end = tail.find("\n}").expect("model must terminate");
    &tail[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_pin_exact_product_and_contract_heads() {
        assert!(SERVER_LOCK.contains("shared-auth/shared-auth-server.rs"));
        assert!(SERVER_LOCK.contains("\"pullRequest\": 156"));
        assert!(SERVER_LOCK.contains("df6033dd7dba3b81b4e6c6c56de8f37b9675bc76"));
        assert!(SERVER_LOCK.contains("75b97b587d6d68065bc862f43a6323e8daa5f4f0"));
        assert!(SERVER_LOCK.contains("73dda80d6c43b043b9cfaa53ae0ecae8ed805abf"));

        assert!(INTERFACES_LOCK.contains("shared-auth/shared-auth-interfaces"));
        assert!(INTERFACES_LOCK.contains("\"pullRequest\": 63"));
        assert!(INTERFACES_LOCK.contains("be30b24eabe813bd0165fde398677c45852ce71c"));
        assert!(INTERFACES_LOCK.contains("5c422d4014468ddca41f16fd49a44bb3301a24d0"));
        assert!(INTERFACES_LOCK.contains("7dc4d3168a622bbcdaac6944b863bfbf3ae03926"));
    }

    #[test]
    fn contract_and_schema_use_persisted_subject_version_vocabulary() {
        assert!(INTERFACES_TSP.contains("subject_version: string;"));
        assert!(!INTERFACES_TSP.contains("derivation_version"));
        assert!(SERVER_SQL.contains("subject_version"));
        assert!(!SERVER_SQL.contains("derivation_version"));
        assert!(SERVER_SQL.contains("opaque-random-v1"));
    }

    #[test]
    fn downstream_assertion_cannot_expose_internal_identity_keys() {
        let assertion = model_body(INTERFACES_TSP, "DownstreamIdentityAssertion");
        assert!(assertion.contains("subject: string;"));
        assert!(assertion.contains("subject_type: DownstreamSubjectType;"));
        assert!(assertion.contains("client_id: string;"));
        assert!(assertion.contains("audience: string;"));
        assert!(assertion.contains("session_id: string;"));
        assert!(!assertion.contains("principal_id"));
        assert!(!assertion.contains("application_account_id"));
        assert!(!assertion.contains("provider_subject"));
    }

    #[test]
    fn upstream_identity_requires_immutable_provider_subject_not_email() {
        let evidence = model_body(INTERFACES_TSP, "UpstreamIdentityEvidence");
        for required in [
            "provider_id: string;",
            "issuer: string;",
            "provider_tenant: string;",
            "provider_subject: string;",
        ] {
            assert!(
                evidence.contains(required),
                "missing immutable identity field: {required}"
            );
        }
        assert!(evidence.contains("verified_email?: string;"));
    }

    #[test]
    fn application_accounts_gain_stable_ids_without_replacing_legacy_key() {
        assert!(SERVER_SQL.contains(
            "add column if not exists application_account_id uuid not null default gen_random_uuid()"
        ));
        assert!(SERVER_SQL.contains("application_accounts_id_unique_idx"));
        assert!(SERVER_SQL.contains("application_account_id"));
    }

    #[test]
    fn each_client_has_one_explicit_sector_and_each_sector_principal_has_one_subject() {
        assert!(SERVER_SQL
            .contains("create table if not exists shared_auth.oauth_client_subject_sectors"));
        assert!(SERVER_SQL.contains("client_id           text        primary key"));
        assert!(SERVER_SQL
            .contains("create table if not exists shared_auth.sector_pairwise_subjects"));
        assert!(SERVER_SQL.contains("primary key (sector_id, shared_user_id)"));
        assert!(SERVER_SQL.contains("subject             text        not null unique"));
    }

    #[test]
    fn pairwise_subject_is_stable_in_sector_and_distinct_across_sectors() {
        let mut registry = PairwiseRegistry::default();
        let first = registry.resolve("sector-a", "principal-1");
        let same_sector = registry.resolve("sector-a", "principal-1");
        let other_sector = registry.resolve("sector-b", "principal-1");
        let other_principal = registry.resolve("sector-a", "principal-2");

        assert_eq!(first, same_sector);
        assert_ne!(first, other_sector);
        assert_ne!(first, other_principal);
    }

    #[test]
    fn read_model_fails_closed_for_inactive_account_client_or_sector() {
        let where_clause = SERVER_SQL
            .split("where aa.status = 'active'")
            .nth(1)
            .expect("active application-account predicate must exist");
        assert!(where_clause.contains("c.status = 'active'"));
        assert!(where_clause.contains("s.active = true"));
    }

    #[test]
    fn sector_contract_and_handoff_are_explicit() {
        let sector = model_body(INTERFACES_TSP, "SubjectSectorContract");
        assert!(sector.contains("sector_id: string;"));
        assert!(sector.contains("sector_identifier: string;"));
        assert!(sector.contains("client_ids: string[];"));
        assert!(sector.contains("subject_version: string;"));

        let handoff = model_body(INTERFACES_TSP, "NetworkSsoHandoff");
        assert!(handoff.contains("target_client_id: string;"));
        assert!(handoff.contains("subject_sector_id: string;"));
        assert!(handoff.contains("authorization_code_id: string;"));
        assert!(handoff.contains("credential_prompted: boolean;"));
    }
}
