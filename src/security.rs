//! Orchestrates the trust gate from fast-path fingerprints through artifact review.
//! It coordinates registry metadata, archive inspection, decisions, and approvals.

use crate::approvals::ApprovalStore;
use crate::archive_inspector::inspect_archive_for_review;
use crate::findings::{ArtifactId, ArtifactReview, Finding};
use crate::lockfile::CargoLock;
use crate::prompt::{Decision, DecisionProvider};
use crate::registry::{RegistryClient, load_index_metadata, stage_one_findings};
use crate::workspace::{Workspace, local_build_dependency_names};
use crate::{Result, error};
use std::collections::{BTreeMap, BTreeSet};

pub struct SecurityGate<'a> {
    pub store: &'a mut ApprovalStore,
    pub registry: &'a dyn RegistryClient,
    pub decisions: &'a mut dyn DecisionProvider,
}

#[derive(Clone, Debug)]
pub struct ReviewOutcome {
    pub fingerprint: String,
    pub fully_remembered: bool,
}

impl SecurityGate<'_> {
    pub fn fast_path(&self, workspace: &Workspace) -> Result<Option<String>> {
        let fingerprint = workspace.fingerprint()?;
        let (lock_hash, manifests_hash) = workspace.component_hashes()?;
        if let Some(previous) = self.store.workspace_record(&workspace.root)
            && !previous.lock_hash.is_empty()
            && previous.lock_hash == lock_hash
            && previous.manifests_hash != manifests_hash
        {
            return Err(error(
                "dependency-audit: Cargo.toml dependency state changed while Cargo.lock did not.\n\nRun:\n\n    cargo forcegenerate-lockfile\n\nto resolve and security-review the changed dependency declarations before Cargo runs.",
            ));
        }
        Ok(self
            .store
            .workspace_matches(&workspace.root, &fingerprint)
            .then_some(fingerprint))
    }

    pub fn review_workspace(&mut self, workspace: &Workspace) -> Result<ReviewOutcome> {
        let lock = CargoLock::parse(&workspace.lockfile)?;
        let fingerprint = workspace.fingerprint()?;
        let local_build_dependencies = local_build_dependency_names(workspace)?;
        self.review_lock_with_roots(&lock, fingerprint, &local_build_dependencies)
    }

    pub fn review_lock(&mut self, lock: &CargoLock, fingerprint: String) -> Result<ReviewOutcome> {
        self.review_lock_with_roots(lock, fingerprint, &BTreeSet::new())
    }

    fn review_lock_with_roots(
        &mut self,
        lock: &CargoLock,
        fingerprint: String,
        local_build_dependencies: &BTreeSet<String>,
    ) -> Result<ReviewOutcome> {
        let artifacts = lock.remote_artifacts()?;
        if artifacts.is_empty() {
            return Ok(ReviewOutcome {
                fingerprint,
                fully_remembered: true,
            });
        }

        // Registry index metadata is the pre-source boundary. Any mismatch aborts here.
        let metadata = load_index_metadata(lock, self.registry)?;
        let stage_one = stage_one_findings(lock, &metadata, local_build_dependencies);
        let mut accepted_once = BTreeSet::<ArtifactId>::new();
        let mut accepted_capabilities = BTreeMap::<ArtifactId, BTreeSet<String>>::new();
        let mut source_authorized = BTreeSet::<ArtifactId>::new();

        for artifact in &artifacts {
            let findings = stage_one.get(artifact).cloned().unwrap_or_default();
            let new_findings = unapproved_findings(self.store, artifact, &findings);
            if new_findings.is_empty() {
                continue;
            }
            match self.decisions.decide(&ArtifactReview {
                artifact: artifact.clone(),
                findings: new_findings.clone(),
                sources: Vec::new(),
            })? {
                Decision::Reject => return Err(rejected(artifact)),
                Decision::AcceptOnce => {
                    accepted_once.insert(artifact.clone());
                }
                Decision::AcceptAndRemember => {
                    accepted_capabilities
                        .entry(artifact.clone())
                        .or_default()
                        .extend(capabilities(&new_findings));
                }
            }
            source_authorized.insert(artifact.clone());
        }

        let inspection_needed: Vec<_> = artifacts
            .iter()
            .filter(|artifact| !self.store.scanner_is_current(artifact))
            .cloned()
            .collect();
        let needs_authorization: Vec<_> = inspection_needed
            .iter()
            .filter(|artifact| {
                !source_authorized.contains(*artifact) && !self.store.has_artifact(artifact)
            })
            .cloned()
            .collect();
        if !needs_authorization.is_empty()
            && !self.decisions.authorize_inspection(&needs_authorization)?
        {
            return Err(error(
                "dependency-audit: isolated source inspection rejected; no crate source was downloaded",
            ));
        }

        let mut all_findings = stage_one;
        let mut inspected = BTreeSet::new();
        for artifact in &inspection_needed {
            let bytes = self.registry.download_archive(artifact)?;
            let inspection = inspect_archive_for_review(&bytes, &artifact.checksum).map_err(
                |inspection_error| {
                    error(format!(
                        "crate {} {} failed memory-only inspection: {inspection_error}",
                        artifact.name, artifact.version
                    ))
                },
            )?;
            all_findings
                .entry(artifact.clone())
                .or_default()
                .extend(inspection.findings);
            inspected.insert(artifact.clone());

            let findings = all_findings.get(artifact).cloned().unwrap_or_default();
            let already_accepted = accepted_capabilities
                .get(artifact)
                .cloned()
                .unwrap_or_default();
            let mut new_findings = unapproved_findings(self.store, artifact, &findings);
            new_findings.retain(|finding| !already_accepted.contains(&finding.capability));
            if !new_findings.is_empty() {
                match self.decisions.decide(&ArtifactReview {
                    artifact: artifact.clone(),
                    findings: new_findings.clone(),
                    sources: inspection.sources,
                })? {
                    Decision::Reject => return Err(rejected(artifact)),
                    Decision::AcceptOnce => {
                        accepted_once.insert(artifact.clone());
                    }
                    Decision::AcceptAndRemember => {
                        accepted_capabilities
                            .entry(artifact.clone())
                            .or_default()
                            .extend(capabilities(&new_findings));
                    }
                }
            }

            if findings.is_empty() {
                self.store.remember(artifact, BTreeSet::new());
            }
        }

        for artifact in &artifacts {
            if inspected.contains(artifact) {
                continue;
            }
            let findings = all_findings.get(artifact).cloned().unwrap_or_default();
            let already_accepted = accepted_capabilities
                .get(artifact)
                .cloned()
                .unwrap_or_default();
            let mut new_findings = unapproved_findings(self.store, artifact, &findings);
            new_findings.retain(|finding| !already_accepted.contains(&finding.capability));
            if !new_findings.is_empty() {
                match self.decisions.decide(&ArtifactReview {
                    artifact: artifact.clone(),
                    findings: new_findings.clone(),
                    sources: Vec::new(),
                })? {
                    Decision::Reject => return Err(rejected(artifact)),
                    Decision::AcceptOnce => {
                        accepted_once.insert(artifact.clone());
                    }
                    Decision::AcceptAndRemember => {
                        accepted_capabilities
                            .entry(artifact.clone())
                            .or_default()
                            .extend(capabilities(&new_findings));
                    }
                }
            }

            // A checksum-verified artifact with no risk findings is remembered after the user
            // authorized inspection. Findings accepted with W are staged in the in-memory store;
            // callers decide when transaction success permits saving it.
            if findings.is_empty() {
                self.store.remember(artifact, BTreeSet::new());
            }
        }

        for (artifact, accepted) in accepted_capabilities {
            self.store.remember(&artifact, accepted);
        }
        let fully_remembered = artifacts.iter().all(|artifact| {
            if accepted_once.contains(artifact) {
                return false;
            }
            let findings = all_findings.get(artifact).cloned().unwrap_or_default();
            let approved = self.store.approved_findings(artifact);
            self.store.scanner_is_current(artifact) && capabilities(&findings).is_subset(&approved)
        });
        Ok(ReviewOutcome {
            fingerprint,
            fully_remembered,
        })
    }
}

fn unapproved_findings(
    store: &ApprovalStore,
    artifact: &ArtifactId,
    findings: &BTreeSet<Finding>,
) -> BTreeSet<Finding> {
    let approved = store.approved_findings(artifact);
    findings
        .iter()
        .filter(|finding| !approved.contains(&finding.capability))
        .cloned()
        .collect()
}

fn capabilities(findings: &BTreeSet<Finding>) -> BTreeSet<String> {
    findings
        .iter()
        .map(|finding| finding.capability.clone())
        .collect()
}

fn rejected(artifact: &ArtifactId) -> crate::BoxError {
    error(format!(
        "dependency-audit: security review rejected {} {}; Cargo was not invoked",
        artifact.name, artifact.version
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::DecisionProvider;
    use crate::registry::{IndexDependency, IndexVersion};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use sha2::{Digest, Sha256};
    use std::cell::Cell;
    use std::io::Write;

    struct FakeRegistry {
        archive: Vec<u8>,
        checksum: String,
        index_requests: Cell<usize>,
        downloads: Cell<usize>,
        build_dependency: bool,
    }

    impl RegistryClient for FakeRegistry {
        fn index_version(&self, artifact: &ArtifactId) -> Result<IndexVersion> {
            self.index_requests.set(self.index_requests.get() + 1);
            Ok(IndexVersion {
                name: artifact.name.clone(),
                vers: artifact.version.clone(),
                deps: if self.build_dependency {
                    vec![IndexDependency {
                        name: "network-helper".into(),
                        req: "1".into(),
                        kind: Some("build".into()),
                        package: None,
                    }]
                } else {
                    Vec::new()
                },
                cksum: self.checksum.clone(),
                yanked: false,
            })
        }

        fn download_archive(&self, _: &ArtifactId) -> Result<Vec<u8>> {
            self.downloads.set(self.downloads.get() + 1);
            Ok(self.archive.clone())
        }
    }

    struct Decisions {
        inspect: bool,
        decisions: Vec<Decision>,
        prompts: usize,
    }

    impl DecisionProvider for Decisions {
        fn authorize_inspection(&mut self, _: &[ArtifactId]) -> Result<bool> {
            Ok(self.inspect)
        }

        fn decide(&mut self, _: &ArtifactReview) -> Result<Decision> {
            self.prompts += 1;
            Ok(self.decisions.remove(0))
        }
    }

    fn fixture(build_script: bool) -> (FakeRegistry, CargoLock) {
        let manifest = if build_script {
            "[package]\nname='demo'\nversion='1.0.0'\nbuild='build.rs'"
        } else {
            "[package]\nname='demo'\nversion='1.0.0'\nbuild=false"
        };
        let source = "fn main(){std::process::Command::new(\"sh\").status().unwrap();}";
        let mut archive = Vec::new();
        {
            let encoder = GzEncoder::new(&mut archive, Compression::default());
            let mut tar = tar::Builder::new(encoder);
            append(&mut tar, "demo-1.0.0/Cargo.toml", manifest.as_bytes());
            append(&mut tar, "demo-1.0.0/build.rs", source.as_bytes());
            tar.into_inner().unwrap().finish().unwrap();
        }
        let checksum = format!("{:x}", Sha256::digest(&archive));
        let lock: CargoLock = toml::from_str(&format!(
            "version=4\n[[package]]\nname='demo'\nversion='1.0.0'\nsource='sparse+http://127.0.0.1/index/'\nchecksum='{checksum}'"
        ))
        .unwrap();
        (
            FakeRegistry {
                archive,
                checksum,
                index_requests: Cell::new(0),
                downloads: Cell::new(0),
                build_dependency: false,
            },
            lock,
        )
    }

    fn append<W: Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, bytes).unwrap();
    }

    #[test]
    fn reject_after_memory_scan_never_persists() {
        let (registry, lock) = fixture(true);
        let directory = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::load(directory.path().join("approvals.toml")).unwrap();
        let mut decisions = Decisions {
            inspect: true,
            decisions: vec![Decision::Reject],
            prompts: 0,
        };
        let mut gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
        };
        assert!(gate.review_lock(&lock, "hash".into()).is_err());
        assert_eq!(registry.downloads.get(), 1);
        assert!(!store.has_artifact(&lock.remote_artifacts().unwrap()[0]));
    }

    #[test]
    fn accept_once_does_not_persist_but_remember_does() {
        for (decision, expected) in [
            (Decision::AcceptOnce, false),
            (Decision::AcceptAndRemember, true),
        ] {
            let (registry, lock) = fixture(true);
            let directory = tempfile::tempdir().unwrap();
            let mut store = ApprovalStore::load(directory.path().join("approvals.toml")).unwrap();
            let mut decisions = Decisions {
                inspect: true,
                decisions: vec![decision],
                prompts: 0,
            };
            let mut gate = SecurityGate {
                store: &mut store,
                registry: &registry,
                decisions: &mut decisions,
            };
            let outcome = gate.review_lock(&lock, "hash".into()).unwrap();
            assert_eq!(outcome.fully_remembered, expected);
            assert_eq!(
                store.has_artifact(&lock.remote_artifacts().unwrap()[0]),
                expected
            );
        }
    }

    #[test]
    fn rejecting_stage_one_downloads_no_archive() {
        let (mut registry, lock) = fixture(false);
        registry.build_dependency = true;
        let directory = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::load(directory.path().join("approvals.toml")).unwrap();
        let mut decisions = Decisions {
            inspect: false,
            decisions: vec![Decision::Reject],
            prompts: 0,
        };
        let mut gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
        };
        assert!(gate.review_lock(&lock, "hash".into()).is_err());
        assert_eq!(registry.downloads.get(), 0);
    }

    #[test]
    fn fast_path_performs_no_registry_or_archive_work() {
        let (registry, _) = fixture(false);
        let workspace_directory = tempfile::tempdir().unwrap();
        std::fs::write(
            workspace_directory.path().join("Cargo.toml"),
            "[package]\nname='local'\nversion='0.1.0'",
        )
        .unwrap();
        std::fs::write(workspace_directory.path().join("Cargo.lock"), "version=4").unwrap();
        let workspace = Workspace::discover(workspace_directory.path()).unwrap();
        let fingerprint = workspace.fingerprint().unwrap();
        let (lock_hash, manifests_hash) = workspace.component_hashes().unwrap();
        let approvals_directory = tempfile::tempdir().unwrap();
        let mut store =
            ApprovalStore::load(approvals_directory.path().join("approvals.toml")).unwrap();
        store.remember_workspace(&workspace.root, &fingerprint, &lock_hash, &manifests_hash);
        let mut decisions = Decisions {
            inspect: false,
            decisions: Vec::new(),
            prompts: 0,
        };
        let gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
        };
        assert_eq!(gate.fast_path(&workspace).unwrap(), Some(fingerprint));
        assert_eq!(registry.index_requests.get(), 0);
        assert_eq!(registry.downloads.get(), 0);
        assert_eq!(decisions.prompts, 0);
    }

    #[test]
    fn manifest_only_drift_is_rejected_before_registry_access() {
        let (registry, _) = fixture(false);
        let workspace_directory = tempfile::tempdir().unwrap();
        let manifest = workspace_directory.path().join("Cargo.toml");
        std::fs::write(&manifest, "[package]\nname='local'\nversion='0.1.0'").unwrap();
        std::fs::write(workspace_directory.path().join("Cargo.lock"), "version=4").unwrap();
        let workspace = Workspace::discover(workspace_directory.path()).unwrap();
        let fingerprint = workspace.fingerprint().unwrap();
        let (lock_hash, manifests_hash) = workspace.component_hashes().unwrap();
        let approvals_directory = tempfile::tempdir().unwrap();
        let mut store =
            ApprovalStore::load(approvals_directory.path().join("approvals.toml")).unwrap();
        store.remember_workspace(&workspace.root, &fingerprint, &lock_hash, &manifests_hash);
        std::fs::write(
            &manifest,
            "[package]\nname='local'\nversion='0.1.0'\n[dependencies]\nnew='1'",
        )
        .unwrap();
        let mut decisions = Decisions {
            inspect: false,
            decisions: Vec::new(),
            prompts: 0,
        };
        let gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
        };
        let message = gate.fast_path(&workspace).unwrap_err().to_string();
        assert!(message.contains("Cargo.toml dependency state changed"));
        assert_eq!(registry.index_requests.get(), 0);
        assert_eq!(registry.downloads.get(), 0);
    }

    #[test]
    fn scanner_upgrade_prompts_for_new_capabilities_on_same_checksum() {
        let (registry, lock) = fixture(true);
        let artifact = lock.remote_artifacts().unwrap().remove(0);
        let approvals_directory = tempfile::tempdir().unwrap();
        let approval_path = approvals_directory.path().join("approvals.toml");
        std::fs::write(
            &approval_path,
            format!(
                "[[approvals]]\nsource={:?}\nname={:?}\nversion={:?}\nchecksum={:?}\napproved_findings=['build-script']\nscanner_version=0\n",
                artifact.source, artifact.name, artifact.version, artifact.checksum
            ),
        )
        .unwrap();
        let mut store = ApprovalStore::load(approval_path).unwrap();
        let mut decisions = Decisions {
            inspect: false,
            decisions: vec![Decision::AcceptAndRemember],
            prompts: 0,
        };
        let mut gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
        };
        let outcome = gate.review_lock(&lock, "hash".into()).unwrap();
        assert!(outcome.fully_remembered);
        assert_eq!(decisions.prompts, 1);
        assert!(
            store
                .approved_findings(&artifact)
                .contains("process-execution")
        );
    }
}
