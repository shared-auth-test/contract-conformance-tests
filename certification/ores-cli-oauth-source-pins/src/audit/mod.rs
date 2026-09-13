use std::path::PathBuf;

use crate::model::CommandReport;

mod oauth_provider_test_source_pins;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryAuditOptions {
    pub path: PathBuf,
    pub profile: String,
    pub additional_required_paths: Vec<String>,
}

#[must_use]
pub fn certify_repository(path: PathBuf) -> CommandReport {
    let options = RepositoryAuditOptions {
        path,
        profile: "baseline".to_owned(),
        additional_required_paths: Vec::new(),
    };
    oauth_provider_test_source_pins::augment_oauth_provider_test_source_pin_audit(
        &options,
        CommandReport::default(),
    )
}
