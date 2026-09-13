use std::fs;
use std::io;
use std::path::Path;

use serde_json::{Value, json};

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const CONTRACT_ROOT: &str = "contracts/oauth-provider";
const TEST_EVIDENCE: &str = "contracts/oauth-provider/test-evidence.json";
const MAX_BYTES: u64 = 256 * 1024;

/// Require OAuth/OIDC `*-test` evidence to identify the exact runtime and
/// peer-authority source revisions it certifies.
///
/// This complements, rather than replaces, TJSV admission. TypeSpec and the
/// independently authored Draft 2020-12 JSON Schema remain peer authorities;
/// TypeSpec-generated Schema B remains comparison evidence only. A green test
/// repository result is not promotion evidence unless it is bound to both the
/// provider runtime head and the authority head that supplied those peer inputs.
pub(super) fn augment_oauth_provider_test_source_pin_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let contract_root = options.path.join(CONTRACT_ROOT);
    match fs::symlink_metadata(&contract_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return report.finalize(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return report.finalize(),
        Err(error) => {
            report.push(
                Finding::error(
                    "oauth-provider-test-source-root-unreadable",
                    format!("OAuth provider contract root could not be inspected: {error}"),
                )
                .with_target(CONTRACT_ROOT),
            );
            return report.finalize();
        }
    }

    let evidence_path = options.path.join(TEST_EVIDENCE);
    let metadata = match fs::symlink_metadata(&evidence_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return report.finalize(),
        Err(error) => {
            report.push(
                Finding::error(
                    "oauth-provider-test-source-evidence-unreadable",
                    format!("OAuth provider test evidence could not be inspected: {error}"),
                )
                .with_target(TEST_EVIDENCE),
            );
            return report.finalize();
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        report.push(
            Finding::error(
                "oauth-provider-test-source-evidence-invalid",
                "OAuth provider test evidence must be a regular non-symlink JSON file",
            )
            .with_target(TEST_EVIDENCE),
        );
        return report.finalize();
    }
    if metadata.len() > MAX_BYTES {
        report.push(
            Finding::error(
                "oauth-provider-test-source-evidence-too-large",
                format!("OAuth provider test evidence exceeds the {MAX_BYTES}-byte bound"),
            )
            .with_target(TEST_EVIDENCE),
        );
        return report.finalize();
    }

    let text = match fs::read_to_string(&evidence_path) {
        Ok(text) => text,
        Err(error) => {
            report.push(
                Finding::error(
                    "oauth-provider-test-source-evidence-not-utf8",
                    format!("OAuth provider test evidence is not readable UTF-8: {error}"),
                )
                .with_target(TEST_EVIDENCE),
            );
            return report.finalize();
        }
    };
    let evidence: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            report.push(
                Finding::error(
                    "oauth-provider-test-source-evidence-json-invalid",
                    format!("OAuth provider test evidence is invalid JSON: {error}"),
                )
                .with_target(TEST_EVIDENCE),
            );
            return report.finalize();
        }
    };

    let Some(object) = evidence.as_object() else {
        report.push(
            Finding::error(
                "oauth-provider-test-source-evidence-root-invalid",
                "OAuth provider test evidence root must be a JSON object",
            )
            .with_target(TEST_EVIDENCE),
        );
        return report.finalize();
    };
    if object.get("schema").and_then(Value::as_str)
        != Some("ores.oauth-provider-test-evidence/v1")
    {
        return report.finalize();
    }

    let provider_source = source_pin(object.get("providerSource"));
    let authority_source = source_pin(object.get("authoritySource"));

    if provider_source.is_none() {
        report.push(
            Finding::error(
                "oauth-provider-test-provider-source-pin-missing",
                "test evidence must bind the exact provider runtime repository and commit",
            )
            .with_target(TEST_EVIDENCE)
            .with_detail("requiredField", json!("providerSource")),
        );
    }
    if authority_source.is_none() {
        report.push(
            Finding::error(
                "oauth-provider-test-authority-source-pin-missing",
                "test evidence must bind the exact interfaces/authority repository and commit",
            )
            .with_target(TEST_EVIDENCE)
            .with_detail("requiredField", json!("authoritySource")),
        );
    }

    if let Some((repository, commit)) = provider_source {
        if !repository.ends_with("-server.rs") && !repository.contains("/shared-auth-server.rs") {
            report.push(
                Finding::error(
                    "oauth-provider-test-provider-source-repository-invalid",
                    "providerSource.repository must identify the runtime server repository",
                )
                .with_target(TEST_EVIDENCE)
                .with_detail("repository", json!(repository)),
            );
        }
        report.insert_metadata("oauthProviderTestProviderSourceSha", json!(commit));
    }
    if let Some((repository, commit)) = authority_source {
        if !repository.ends_with("-interfaces") {
            report.push(
                Finding::error(
                    "oauth-provider-test-authority-source-repository-invalid",
                    "authoritySource.repository must identify an *-interfaces repository",
                )
                .with_target(TEST_EVIDENCE)
                .with_detail("repository", json!(repository)),
            );
        }
        report.insert_metadata("oauthProviderTestAuthoritySourceSha", json!(commit));
    }

    report.finalize()
}

fn source_pin(value: Option<&Value>) -> Option<(&str, &str)> {
    let object = value?.as_object()?;
    let repository = object.get("repository")?.as_str()?;
    let commit = object.get("commit")?.as_str()?;
    if valid_repository(repository) && is_sha40(commit) {
        Some((repository, commit))
    } else {
        None
    }
}

fn valid_repository(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !name.is_empty()
        && !owner.contains(char::is_whitespace)
        && !name.contains(char::is_whitespace)
        && !name.contains('/')
}

fn is_sha40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::augment_oauth_provider_test_source_pin_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    const SERVER_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const INTERFACES_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn audit(evidence: &str) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        let contract = root.path().join("contracts/oauth-provider");
        fs::create_dir_all(&contract).expect("contract root");
        fs::write(contract.join("test-evidence.json"), evidence).expect("test evidence");
        augment_oauth_provider_test_source_pin_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    fn valid() -> String {
        format!(
            r#"{{
  "schema": "ores.oauth-provider-test-evidence/v1",
  "providerSource": {{
    "repository": "shared-auth/shared-auth-server.rs",
    "commit": "{SERVER_SHA}"
  }},
  "authoritySource": {{
    "repository": "shared-auth/shared-auth-interfaces",
    "commit": "{INTERFACES_SHA}"
  }}
}}"#
        )
    }

    #[test]
    fn accepts_exact_runtime_and_authority_source_pins() {
        let report = audit(&valid());
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert_eq!(
            report
                .metadata
                .get("oauthProviderTestProviderSourceSha")
                .and_then(serde_json::Value::as_str),
            Some(SERVER_SHA)
        );
        assert_eq!(
            report
                .metadata
                .get("oauthProviderTestAuthoritySourceSha")
                .and_then(serde_json::Value::as_str),
            Some(INTERFACES_SHA)
        );
    }

    #[test]
    fn rejects_evidence_without_provider_source_pin() {
        let evidence = valid().replace(
            &format!(
                "  \"providerSource\": {{\n    \"repository\": \"shared-auth/shared-auth-server.rs\",\n    \"commit\": \"{SERVER_SHA}\"\n  }},\n"
            ),
            "",
        );
        let report = audit(&evidence);
        assert!(report.findings.iter().any(|finding| {
            finding.code == "oauth-provider-test-provider-source-pin-missing"
        }));
    }

    #[test]
    fn rejects_evidence_without_authority_source_pin() {
        let evidence = valid().replace(
            &format!(
                ",\n  \"authoritySource\": {{\n    \"repository\": \"shared-auth/shared-auth-interfaces\",\n    \"commit\": \"{INTERFACES_SHA}\"\n  }}\n"
            ),
            "\n",
        );
        let report = audit(&evidence);
        assert!(report.findings.iter().any(|finding| {
            finding.code == "oauth-provider-test-authority-source-pin-missing"
        }));
    }

    #[test]
    fn rejects_mutable_or_wrong_family_source_pins() {
        let evidence = valid()
            .replace(SERVER_SHA, "main")
            .replace("shared-auth/shared-auth-interfaces", "shared-auth/shared-auth-clients");
        let report = audit(&evidence);
        assert!(report.findings.iter().any(|finding| {
            finding.code == "oauth-provider-test-provider-source-pin-missing"
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.code == "oauth-provider-test-authority-source-repository-invalid"
                || finding.code == "oauth-provider-test-authority-source-pin-missing"
        }));
    }

    #[test]
    fn ignores_non_oauth_evidence_versions() {
        let report = audit(r#"{"schema":"other/v1"}"#);
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }
}
