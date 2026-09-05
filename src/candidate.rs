//! Resolves dependency-changing commands in a temporary workspace and Cargo home.
//! It keeps candidate locks isolated and rejects any resolution that exposes source.

use crate::cargo_runner::{CargoRunner, DirectCargoRunner};
use crate::command_policy::{CommandPolicy, Invocation};
use crate::lockfile::CargoLock;
use crate::{Result, error};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Candidate {
    temporary: TemporaryDirectory,
    pub workspace_root: PathBuf,
    pub working_directory: PathBuf,
    pub lockfile: PathBuf,
    pub cargo_home: PathBuf,
    pub args: Vec<String>,
}

impl Candidate {
    pub fn lock(&self) -> Result<CargoLock> {
        CargoLock::parse(&self.lockfile)
    }

    pub fn root(&self) -> &Path {
        self.temporary.path()
    }
}

pub fn resolve_candidate(
    runner: &DirectCargoRunner,
    real_workspace_root: &Path,
    real_cwd: &Path,
    original_args: &[String],
    invocation: &Invocation,
) -> Result<Candidate> {
    let real_command = match invocation.forced_command.as_deref() {
        Some(command) => command,
        None if invocation.policy == CommandPolicy::ReviewedDependencyRemoval => "remove",
        None => {
            return Err(error(
                "internal error: candidate resolution requires a reviewed mutation command",
            ));
        }
    };
    if real_command == "install" {
        return Err(error(
            "internal error: unsupported install operation reached candidate resolution",
        ));
    }

    let temporary = TemporaryDirectory::new("cargo-wrapper-candidate")?;
    let workspace_root = temporary.path().join("workspace");
    copy_local_workspace(real_workspace_root, &workspace_root)?;
    let working_directory = real_cwd
        .strip_prefix(real_workspace_root)
        .map(|relative| workspace_root.join(relative))
        .unwrap_or_else(|_| workspace_root.clone());
    let cargo_home = temporary.path().join("cargo-home");
    fs::create_dir(&cargo_home)?;
    let mut args = original_args.to_vec();
    args[invocation.command_index] = real_command.to_owned();
    rewrite_manifest_path(&mut args, real_cwd, real_workspace_root, &workspace_root)?;

    let status = runner.run(&args, &working_directory, Some(&cargo_home))?;
    if !status.success() {
        return Err(error(format!(
            "dependency-audit: isolated candidate `cargo {real_command}` failed with status {status}"
        )));
    }
    assert_no_downloaded_source(&cargo_home)?;
    let lockfile = workspace_root.join("Cargo.lock");
    if !lockfile.is_file() {
        return Err(error(
            "isolated candidate operation did not produce Cargo.lock",
        ));
    }
    Ok(Candidate {
        temporary,
        workspace_root,
        working_directory,
        lockfile,
        cargo_home,
        args,
    })
}

fn rewrite_manifest_path(
    args: &mut [String],
    real_cwd: &Path,
    real_root: &Path,
    candidate_root: &Path,
) -> Result<()> {
    let end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let mut index = 0;
    while index < end {
        if args[index] == "--manifest-path" {
            if let Some(value) = args.get_mut(index + 1) {
                let path = PathBuf::from(&*value);
                let path = if path.is_absolute() {
                    path
                } else {
                    real_cwd.join(path)
                }
                .canonicalize()?;
                let relative = path
                    .strip_prefix(real_root)
                    .map_err(|_| error("--manifest-path is outside the reviewed workspace"))?;
                *value = candidate_root.join(relative).to_string_lossy().into_owned();
            }
            index += 2;
            continue;
        }
        if let Some(value) = args[index].strip_prefix("--manifest-path=") {
            let path = PathBuf::from(value);
            let path = if path.is_absolute() {
                path
            } else {
                real_cwd.join(path)
            }
            .canonicalize()?;
            let relative = path
                .strip_prefix(real_root)
                .map_err(|_| error("--manifest-path is outside the reviewed workspace"))?;
            args[index] = format!(
                "--manifest-path={}",
                candidate_root.join(relative).display()
            );
        }
        index += 1;
    }
    Ok(())
}

fn assert_no_downloaded_source(cargo_home: &Path) -> Result<()> {
    for path in [
        cargo_home.join("registry/cache"),
        cargo_home.join("registry/src"),
        cargo_home.join("git/checkouts"),
        cargo_home.join("git/db"),
    ] {
        if path.exists() && directory_has_files(&path)? {
            return Err(error(format!(
                "dependency-audit: candidate resolution exposed dependency source at {}; aborting because this Cargo behavior violates the index-only boundary",
                path.display()
            )));
        }
    }
    Ok(())
}

fn directory_has_files(path: &Path) -> Result<bool> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            || (entry.file_type()?.is_dir() && directory_has_files(&entry.path())?)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn copy_local_workspace(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_str(), Some("target" | ".git")) {
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(&name);
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(error(format!(
                "dependency-audit: refusing to mirror workspace symlink {} during candidate resolution",
                source_path.display()
            )));
        }
        if file_type.is_dir() {
            copy_local_workspace(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for attempt in 0..100u32 {
            let path = std::env::temp_dir()
                .join(format!("{prefix}-{}-{nonce}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(create_error) if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(create_error) => return Err(create_error.into()),
            }
        }
        Err(error("cannot allocate a private candidate directory"))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
pub struct WorkspaceSnapshot {
    files: Vec<(PathBuf, Option<Vec<u8>>)>,
}

impl WorkspaceSnapshot {
    pub fn capture(root: &Path) -> Result<Self> {
        let mut paths = Vec::new();
        collect_transaction_files(root, &mut paths)?;
        paths.push(root.join("Cargo.lock"));
        paths.sort();
        paths.dedup();
        let files = paths
            .into_iter()
            .map(|path| {
                let bytes = match fs::read(&path) {
                    Ok(bytes) => Some(bytes),
                    Err(read_error) if read_error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(read_error) => return Err(read_error.into()),
                };
                Ok((path, bytes))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { files })
    }

    pub fn restore(&self) -> Result<()> {
        for (path, contents) in &self.files {
            match contents {
                Some(contents) => fs::write(path, contents)?,
                None if path.exists() => fs::remove_file(path)?,
                None => {}
            }
        }
        Ok(())
    }
}

fn collect_transaction_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_file() && name == "Cargo.toml" {
            files.push(entry.path());
        } else if file_type.is_dir()
            && !matches!(name.to_str(), Some("target" | ".git" | ".cargo" | "vendor"))
        {
            collect_transaction_files(&entry.path(), files)?;
        }
    }
    Ok(())
}

pub fn locks_match(candidate: &CargoLock, real: &CargoLock) -> Result<bool> {
    Ok(candidate.remote_artifacts()? == real.remote_artifacts()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_restores_changed_and_new_transaction_files() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("Cargo.toml"), "old").unwrap();
        let snapshot = WorkspaceSnapshot::capture(directory.path()).unwrap();
        fs::write(directory.path().join("Cargo.toml"), "new").unwrap();
        fs::write(directory.path().join("Cargo.lock"), "new lock").unwrap();
        snapshot.restore().unwrap();
        assert_eq!(
            fs::read_to_string(directory.path().join("Cargo.toml")).unwrap(),
            "old"
        );
        assert!(!directory.path().join("Cargo.lock").exists());
    }
}
