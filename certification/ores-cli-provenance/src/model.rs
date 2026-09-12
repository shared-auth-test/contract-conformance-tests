use std::collections::BTreeMap;

use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct CommandReport {
    pub findings: Vec<Finding>,
    pub metadata: BTreeMap<String, Value>,
}

impl CommandReport {
    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn insert_metadata(&mut self, key: impl Into<String>, value: Value) {
        self.metadata.insert(key.into(), value);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub code: String,
    pub message: String,
    pub target: Option<String>,
    pub details: BTreeMap<String, Value>,
}

impl Finding {
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            target: None,
            details: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: Value) -> Self {
        self.details.insert(key.into(), value);
        self
    }
}
