use std::path::PathBuf;

use crate::model::CommandReport;

mod tjsv_generated_schema_provenance;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryAuditOptions {
    pub path: PathBuf,
}

#[must_use]
pub fn certify_repository(path: PathBuf) -> CommandReport {
    let options = RepositoryAuditOptions { path };
    tjsv_generated_schema_provenance::augment_tjsv_generated_schema_provenance_audit(
        &options,
        CommandReport::default(),
    )
}
