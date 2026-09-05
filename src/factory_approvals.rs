//! Parses, validates, previews, and installs the optional embedded trust bundle.
//! Every entry is bound to an exact registry artifact and current scanner version.

use crate::approvals::ApprovalStore;
use crate::findings::ArtifactId;
use crate::scanner::SCANNER_VERSION;
use crate::{Result, error};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const EMBEDDED_BUNDLE: &str = include_str!("../factory-approvals.toml");
const SUPPORTED_SCHEMA_VERSION: u32 = 2;
const KNOWN_CAPABILITIES: &[&str] = &[
    "build-dependencies",
    "build-script",
    "build-time-closure",
    "build-time-network-family",
    "command-target",
    "dynamic-loading-or-ffi",
    "environment-access",
    "filesystem-modification",
    "high-risk-combination",
    "network-access",
    "proc-macro",
    "process-execution",
    "shell-or-downloader",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryBundle {
    pub schema_version: u32,
    pub bundle_version: String,
    pub reviewed_at: String,
    pub description: String,
    pub source: String,
    pub scanner_version: u32,
    pub approval_groups: Vec<FactoryApprovalGroup>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryApprovalGroup {
    pub name: String,
    #[serde(default)]
    pub approved_findings: BTreeSet<String>,
    pub releases: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct FactoryApproval {
    pub source: String,
    pub name: String,
    pub version: String,
    pub checksum: String,
    pub scanner_version: u32,
    pub approved_findings: BTreeSet<String>,
}

impl FactoryApproval {
    pub fn artifact(&self) -> ArtifactId {
        ArtifactId {
            source: self.source.clone(),
            name: self.name.clone(),
            version: self.version.clone(),
            checksum: self.checksum.clone(),
        }
    }
}

impl FactoryBundle {
    pub fn embedded() -> Result<Self> {
        let bundle: Self = toml::from_str(EMBEDDED_BUNDLE)?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn from_approvals(
        bundle_version: String,
        reviewed_at: String,
        description: String,
        approvals: Vec<FactoryApproval>,
    ) -> Result<Self> {
        let Some(first) = approvals.first() else {
            return Err(error("factory trust bundle contains no approvals"));
        };
        let source = first.source.clone();
        let scanner_version = first.scanner_version;
        let mut grouped = BTreeMap::<(String, BTreeSet<String>), BTreeMap<String, String>>::new();
        for approval in approvals {
            if approval.source != source || approval.scanner_version != scanner_version {
                return Err(error(
                    "factory approvals must use one registry source and scanner version",
                ));
            }
            let name = approval.name;
            let releases = grouped
                .entry((name.clone(), approval.approved_findings))
                .or_default();
            if let Some(existing) =
                releases.insert(approval.version.clone(), approval.checksum.clone())
                && existing != approval.checksum
            {
                return Err(error(format!(
                    "factory bundle contains conflicting checksums for {} {}",
                    name, approval.version
                )));
            }
        }
        let bundle = Self {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            bundle_version,
            reviewed_at,
            description,
            source,
            scanner_version,
            approval_groups: grouped
                .into_iter()
                .map(
                    |((name, approved_findings), releases)| FactoryApprovalGroup {
                        name,
                        approved_findings,
                        releases,
                    },
                )
                .collect(),
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn approvals(&self) -> impl Iterator<Item = FactoryApproval> + '_ {
        self.approval_groups.iter().flat_map(|group| {
            group
                .releases
                .iter()
                .map(|(version, checksum)| FactoryApproval {
                    source: self.source.clone(),
                    name: group.name.clone(),
                    version: version.clone(),
                    checksum: checksum.clone(),
                    scanner_version: self.scanner_version,
                    approved_findings: group.approved_findings.clone(),
                })
        })
    }

    pub fn approval_count(&self) -> usize {
        self.approval_groups
            .iter()
            .map(|group| group.releases.len())
            .sum()
    }

    pub fn install(&self, store: &mut ApprovalStore) -> Result<usize> {
        self.validate()?;
        let mut changed = 0;
        for entry in self.approvals() {
            let artifact = entry.artifact();
            let already_current = store.scanner_is_current(&artifact)
                && entry
                    .approved_findings
                    .is_subset(&store.approved_findings(&artifact));
            if !already_current {
                changed += 1;
                store.remember(&artifact, entry.approved_findings.clone());
            }
        }
        store.remember_factory_bundle(&self.bundle_version);
        Ok(changed)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(error(format!(
                "unsupported factory trust bundle schema {}",
                self.schema_version
            )));
        }
        if self.approval_groups.is_empty() || self.approval_count() == 0 {
            return Err(error("factory trust bundle contains no approvals"));
        }
        if self.scanner_version != SCANNER_VERSION {
            return Err(error(format!(
                "factory bundle uses scanner version {}, expected {}",
                self.scanner_version, SCANNER_VERSION
            )));
        }
        if self.source != "registry+https://github.com/rust-lang/crates.io-index" {
            return Err(error(format!(
                "factory bundle has unsupported source {}",
                self.source
            )));
        }

        let mut identities = BTreeSet::new();
        let mut published_checksums = BTreeMap::new();
        for group in &self.approval_groups {
            if group.name.trim().is_empty() || group.releases.is_empty() {
                return Err(error("factory approval group is empty"));
            }
            for capability in &group.approved_findings {
                if !KNOWN_CAPABILITIES.contains(&capability.as_str()) {
                    return Err(error(format!(
                        "factory approval for {} contains unknown capability {capability}",
                        group.name
                    )));
                }
            }
            for (version, checksum) in &group.releases {
                semver::Version::parse(version)?;
                if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(error(format!(
                        "factory approval for {} {} has an invalid SHA-256 checksum",
                        group.name, version
                    )));
                }
                if !identities.insert((group.name.as_str(), version.as_str(), checksum.as_str())) {
                    return Err(error(format!(
                        "duplicate factory approval for {} {}",
                        group.name, version
                    )));
                }
                if let Some(existing_checksum) = published_checksums
                    .insert((group.name.as_str(), version.as_str()), checksum.as_str())
                    && existing_checksum != checksum
                {
                    return Err(error(format!(
                        "factory bundle contains conflicting checksums for {} {}",
                        group.name, version
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_bundle_is_valid_and_exact() {
        let bundle = FactoryBundle::embedded().unwrap();
        assert_eq!(bundle.approval_count(), 2_764);
        assert_eq!(bundle.bundle_version, "2026-09-04-fairgate");
    }

    #[test]
    fn identical_crate_decisions_group_exact_release_checksums() {
        let bundle = FactoryBundle::embedded().unwrap();
        let group = bundle
            .approval_groups
            .iter()
            .find(|group| group.name == "addr2line")
            .unwrap();

        assert_eq!(group.releases.len(), 4);
        assert_eq!(
            group.releases.get("0.24.1").map(String::as_str),
            Some("f5fb1d8e4442bd405fdfd1dacb42792696b0cf9cb15882e5d097b742a676d375")
        );
        assert_eq!(
            group.releases.get("0.24.2").map(String::as_str),
            Some("dfbe277e56a376000877090da837660b4427aad530e3028d44e0bffe4f89a1c1")
        );
        assert!(!group.releases.contains_key("0.24.0"));
    }

    #[test]
    fn install_merges_exact_entries_and_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("approvals.toml");
        let mut store = ApprovalStore::load(path.clone()).unwrap();
        let bundle = FactoryBundle::embedded().unwrap();

        assert_eq!(bundle.install(&mut store).unwrap(), bundle.approval_count());
        assert_eq!(bundle.install(&mut store).unwrap(), 0);
        assert!(
            store
                .installed_factory_bundles()
                .contains(&bundle.bundle_version)
        );
        for entry in bundle.approvals() {
            let artifact = entry.artifact();
            assert!(store.has_artifact(&artifact));
            assert!(store.scanner_is_current(&artifact));
            assert!(
                entry
                    .approved_findings
                    .is_subset(&store.approved_findings(&artifact))
            );
        }
        store.save().unwrap();
        let reloaded = ApprovalStore::load(path).unwrap();
        assert!(
            reloaded
                .installed_factory_bundles()
                .contains(&bundle.bundle_version)
        );
    }

    #[test]
    fn an_unlisted_version_or_checksum_is_not_trusted() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::load(directory.path().join("approvals.toml")).unwrap();
        let bundle = FactoryBundle::embedded().unwrap();
        bundle.install(&mut store).unwrap();
        let first = bundle.approvals().next().unwrap();

        let mut changed_version = first.artifact();
        changed_version.version = "1.0.108".into();
        assert!(!store.has_artifact(&changed_version));

        let mut older_version = first.artifact();
        older_version.version = "0.0.1".into();
        assert!(!store.has_artifact(&older_version));

        let mut changed_checksum = first.artifact();
        changed_checksum.checksum = "0".repeat(64);
        assert!(!store.has_artifact(&changed_checksum));
    }

    #[test]
    fn conflicting_checksums_for_one_published_version_are_rejected() {
        let mut bundle = FactoryBundle::embedded().unwrap();
        let mut conflicting = bundle.approval_groups[0].clone();
        let version = conflicting.releases.keys().next().unwrap().clone();
        conflicting.releases.insert(version, "0".repeat(64));
        bundle.approval_groups.push(conflicting);

        let failure = bundle.validate().unwrap_err().to_string();
        assert!(failure.contains("conflicting checksums"));
    }

    #[test]
    fn current_serde_entries_match_the_repository_lockfile() {
        let bundle = FactoryBundle::embedded().unwrap();
        let lock: toml::Value = toml::from_str(include_str!("../Cargo.lock")).unwrap();
        let packages = lock.get("package").and_then(toml::Value::as_array).unwrap();

        for package in packages.iter().filter(|package| {
            matches!(
                package.get("name").and_then(toml::Value::as_str),
                Some(
                    "proc-macro2"
                        | "quote"
                        | "serde"
                        | "serde_core"
                        | "serde_derive"
                        | "syn"
                        | "unicode-ident"
                )
            )
        }) {
            let matching = bundle.approvals().any(|entry| {
                Some(entry.name.as_str()) == package.get("name").and_then(toml::Value::as_str)
                    && Some(entry.version.as_str())
                        == package.get("version").and_then(toml::Value::as_str)
                    && Some(entry.source.as_str())
                        == package.get("source").and_then(toml::Value::as_str)
                    && Some(entry.checksum.as_str())
                        == package.get("checksum").and_then(toml::Value::as_str)
            });
            assert!(
                matching,
                "{} {} is absent or has different immutable metadata in the bundle",
                package.get("name").and_then(toml::Value::as_str).unwrap(),
                package
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .unwrap()
            );
        }
    }
}
