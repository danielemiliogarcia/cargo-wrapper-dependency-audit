//! Discovers Cargo workspaces and fingerprints dependency-relevant local state.
//! Only lockfiles and manifests participate in the normal-build trust fast path.

use crate::{Result, error};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Workspace {
    pub root: PathBuf,
    pub lockfile: PathBuf,
    pub manifests: Vec<PathBuf>,
}

impl Workspace {
    pub fn discover(start: &Path) -> Result<Self> {
        let start = start.canonicalize()?;
        let directory = if start.is_dir() {
            start.as_path()
        } else {
            start
                .parent()
                .ok_or_else(|| error("invalid working directory"))?
        };
        let root = directory
            .ancestors()
            .find(|ancestor| ancestor.join("Cargo.lock").is_file())
            .map(Path::to_path_buf)
            .or_else(|| project_root(directory).ok())
            .ok_or_else(|| {
                error("dependency-audit: no Cargo.toml was found in this directory or its parents")
            })?;
        let lockfile = root.join("Cargo.lock");
        if !lockfile.is_file() {
            return Err(error(missing_lock_message()));
        }
        let mut manifests = Vec::new();
        collect_manifests(&root, &mut manifests)?;
        manifests.sort();
        if manifests.is_empty() {
            return Err(error(
                "dependency-audit: no Cargo.toml found for locked workspace",
            ));
        }
        Ok(Self {
            root,
            lockfile,
            manifests,
        })
    }

    pub fn fingerprint(&self) -> Result<String> {
        let (lock_hash, manifests_hash) = self.component_hashes()?;
        let mut hasher = Sha256::new();
        hasher.update(lock_hash.as_bytes());
        hasher.update(manifests_hash.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn component_hashes(&self) -> Result<(String, String)> {
        let mut lock_hasher = Sha256::new();
        hash_named_file(&mut lock_hasher, Path::new("Cargo.lock"), &self.lockfile)?;
        let mut manifest_hasher = Sha256::new();
        for manifest in &self.manifests {
            let relative = manifest.strip_prefix(&self.root)?;
            hash_named_file(&mut manifest_hasher, relative, manifest)?;
        }
        Ok((
            format!("{:x}", lock_hasher.finalize()),
            format!("{:x}", manifest_hasher.finalize()),
        ))
    }
}

pub fn project_root(start: &Path) -> Result<PathBuf> {
    let start = start.canonicalize()?;
    let directory = if start.is_dir() {
        start.as_path()
    } else {
        start
            .parent()
            .ok_or_else(|| error("invalid working directory"))?
    };
    let manifests: Vec<_> = directory
        .ancestors()
        .filter(|ancestor| ancestor.join("Cargo.toml").is_file())
        .collect();
    for ancestor in &manifests {
        let contents = fs::read_to_string(ancestor.join("Cargo.toml"))?;
        let manifest: toml::Value = toml::from_str(&contents)?;
        if manifest.get("workspace").is_some() {
            return Ok((*ancestor).to_path_buf());
        }
    }
    manifests
        .first()
        .map(|path| (*path).to_path_buf())
        .ok_or_else(|| {
            error("dependency-audit: no Cargo.toml was found in this directory or its parents")
        })
}

pub fn local_build_dependency_names(
    workspace: &Workspace,
) -> Result<std::collections::BTreeSet<String>> {
    let mut names = std::collections::BTreeSet::new();
    for path in &workspace.manifests {
        let contents = fs::read_to_string(path)?;
        let manifest: toml::Value = toml::from_str(&contents)?;
        collect_build_dependencies(&manifest, &mut names);
    }
    Ok(names)
}

fn collect_build_dependencies(
    manifest: &toml::Value,
    names: &mut std::collections::BTreeSet<String>,
) {
    if let Some(dependencies) = manifest
        .get("build-dependencies")
        .and_then(toml::Value::as_table)
    {
        for (declared_name, specification) in dependencies {
            let actual = specification
                .get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(declared_name);
            names.insert(actual.to_owned());
        }
    }
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            collect_build_dependencies(target, names);
        }
    }
}

fn hash_named_file(hasher: &mut Sha256, name: &Path, path: &Path) -> Result<()> {
    let bytes = fs::read(path)?;
    hasher.update((name.as_os_str().len() as u64).to_le_bytes());
    hasher.update(name.to_string_lossy().as_bytes());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

fn collect_manifests(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_file() && entry.file_name() == "Cargo.toml" {
            output.push(path);
        } else if file_type.is_dir() {
            let name = entry.file_name();
            if matches!(name.to_str(), Some("target" | ".git" | ".cargo" | "vendor")) {
                continue;
            }
            collect_manifests(&path, output)?;
        }
    }
    Ok(())
}

pub fn missing_lock_message() -> &'static str {
    "dependency-audit: Cargo.lock is missing.\n\n\
     The wrapper will not allow Cargo to resolve, download, or compile\n\
     an unreviewed dependency graph implicitly.\n\n\
     Run:\n\n    cargo forcegenerate-lockfile\n\n\
     to resolve and security-review the initial dependency set."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_tracks_only_lock_and_manifests() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("src")).unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='x'\nversion='0.1.0'",
        )
        .unwrap();
        fs::write(directory.path().join("Cargo.lock"), "version = 4").unwrap();
        fs::write(directory.path().join("src/lib.rs"), "one").unwrap();
        let workspace = Workspace::discover(directory.path()).unwrap();
        let first = workspace.fingerprint().unwrap();
        fs::write(directory.path().join("src/lib.rs"), "two").unwrap();
        assert_eq!(first, workspace.fingerprint().unwrap());
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='x'\nversion='0.2.0'",
        )
        .unwrap();
        assert_ne!(first, workspace.fingerprint().unwrap());
    }

    #[test]
    fn missing_lock_fails_before_cargo() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='x'\nversion='0.1.0'",
        )
        .unwrap();
        let error = Workspace::discover(directory.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("forcegenerate-lockfile"));
    }
}
