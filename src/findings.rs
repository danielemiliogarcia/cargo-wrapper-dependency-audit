//! Provides shared identities and review findings for registry artifacts.
//! These ordered data types connect scanning, prompting, and persistent approvals.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Finding {
    pub capability: String,
    pub detail: String,
    #[serde(default)]
    pub evidence: Vec<SourceEvidence>,
}

impl Finding {
    pub fn new(capability: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            detail: detail.into(),
            evidence: Vec::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: Option<SourceEvidence>) -> Self {
        self.evidence.extend(evidence);
        self
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SourceEvidence {
    pub path: String,
    pub first_line: usize,
    pub focus_line: usize,
    pub lines: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ReviewSource {
    pub path: String,
    pub contents: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ArtifactId {
    pub source: String,
    pub name: String,
    pub version: String,
    pub checksum: String,
}

#[derive(Clone, Debug)]
pub struct ArtifactReview {
    pub artifact: ArtifactId,
    pub findings: BTreeSet<Finding>,
    pub sources: Vec<ReviewSource>,
}

impl ArtifactReview {
    pub fn capability_set(&self) -> BTreeSet<String> {
        self.findings
            .iter()
            .map(|finding| finding.capability.clone())
            .collect()
    }
}

pub fn has_high_risk_combination(findings: &BTreeSet<Finding>) -> bool {
    let kinds: BTreeSet<_> = findings
        .iter()
        .map(|finding| finding.capability.as_str())
        .collect();
    kinds.contains("network-access")
        && (kinds.contains("process-execution") || kinds.contains("filesystem-modification"))
}
