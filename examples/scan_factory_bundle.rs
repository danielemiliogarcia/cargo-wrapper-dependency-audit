//! Maintainer tool that statically scans exact crates.io artifacts from lockfile inventory.
//! It verifies archive checksums, never extracts source, and excludes RustSec-flagged entries.

use cargo_wrapper_dependency_audit::archive_inspector::inspect_archive;
use cargo_wrapper_dependency_audit::factory_approvals::{FactoryApproval, FactoryBundle};
use cargo_wrapper_dependency_audit::registry::MAX_ARCHIVE_BYTES;
use cargo_wrapper_dependency_audit::scanner::SCANNER_VERSION;
use cargo_wrapper_dependency_audit::{Result, error};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const NETWORK_FAMILIES: &[&str] = &[
    "attohttpc",
    "curl",
    "hyper",
    "isahc",
    "native-tls",
    "reqwest",
    "rustls",
    "ureq",
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Artifact {
    name: String,
    version: String,
    source: String,
    checksum: String,
}

#[derive(Debug)]
struct Inventory {
    artifacts: Vec<Artifact>,
    manifest_count: usize,
    lockfile_count: usize,
    unlocked_manifests: Vec<PathBuf>,
    unsupported_remote_artifacts: Vec<(String, String, String)>,
}

#[derive(Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<LockedPackage>,
}

#[derive(Deserialize)]
struct LockedPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

#[derive(Debug)]
struct ScanResult {
    artifact: Artifact,
    findings: BTreeSet<String>,
    error: Option<String>,
    blocked: bool,
}

fn main() {
    if let Err(scan_error) = run() {
        eprintln!("{scan_error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() < 4 {
        return Err(error(
            "usage: cargo run --example scan_factory_bundle -- <source-root>... <rustsec-blocklist> <output.toml> <report.md>",
        ));
    }
    let output_arguments = arguments.len() - 3;
    let source_roots = &arguments[..output_arguments];
    let blocked_path = &arguments[output_arguments];
    let output_path = &arguments[output_arguments + 1];
    let report_path = &arguments[output_arguments + 2];

    let inventory = read_inventory(source_roots)?;
    let blocked = read_blocklist(Path::new(blocked_path))?;
    let cache = cached_archives()?;
    let queue = Arc::new(Mutex::new(VecDeque::from(inventory.artifacts)));
    let results = Arc::new(Mutex::new(Vec::new()));
    let workers = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .min(16);
    let mut handles = Vec::new();

    for _ in 0..workers {
        let queue = Arc::clone(&queue);
        let results = Arc::clone(&results);
        let blocked = Arc::clone(&blocked);
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            let agent = ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout_read(Duration::from_secs(45))
                .redirects(3)
                .build();
            loop {
                let Some(artifact) = queue.lock().unwrap().pop_front() else {
                    break;
                };
                let archive_name = format!("{}-{}.crate", artifact.name, artifact.version);
                let bytes = cache
                    .get(&archive_name)
                    .map(|path| fs::read(path).map_err(Into::into))
                    .unwrap_or_else(|| download(&agent, &artifact));
                let (findings, scan_error) =
                    match bytes.and_then(|bytes| inspect_archive(&bytes, &artifact.checksum)) {
                        Ok(findings) => (
                            findings
                                .into_iter()
                                .map(|finding| finding.capability)
                                .collect(),
                            None,
                        ),
                        Err(scan_error) => (BTreeSet::new(), Some(scan_error.to_string())),
                    };
                let is_blocked = blocked.contains(&(
                    artifact.name.clone(),
                    artifact.version.clone(),
                    artifact.checksum.clone(),
                ));
                results.lock().unwrap().push(ScanResult {
                    artifact,
                    findings,
                    error: scan_error,
                    blocked: is_blocked,
                });
            }
        }));
    }
    for handle in handles {
        handle
            .join()
            .map_err(|_| error("factory scan worker panicked"))?;
    }

    let mut results = Arc::into_inner(results)
        .expect("workers released scan results")
        .into_inner()
        .unwrap();
    results.sort_by(|left, right| left.artifact.cmp(&right.artifact));

    let approvals = results
        .iter()
        .filter(|result| result.error.is_none() && !result.blocked)
        .map(|result| {
            let mut findings = result.findings.clone();
            // Factory trust means this exact artifact is accepted even when a future graph places
            // it in build-time closure. Network-family closure remains explicit in stored data.
            findings.insert("build-time-closure".to_owned());
            if NETWORK_FAMILIES.contains(&result.artifact.name.as_str()) {
                findings.insert("build-time-network-family".to_owned());
            }
            FactoryApproval {
                source: result.artifact.source.clone(),
                name: result.artifact.name.clone(),
                version: result.artifact.version.clone(),
                checksum: result.artifact.checksum.clone(),
                scanner_version: SCANNER_VERSION,
                approved_findings: findings,
            }
        })
        .collect();
    let bundle = FactoryBundle::from_approvals(
        "2026-09-04-fairgate".to_owned(),
        "2026-09-04".to_owned(),
        "Exact crates.io artifacts locked by the source Cargo Wrapper and FAIRGATE projects, checksum-verified and statically scanned by Dependency Audit; RustSec-flagged artifacts excluded".to_owned(),
        approvals,
    )?;
    let serialized_bundle = toml::to_string_pretty(&bundle)?;
    fs::write(
        output_path,
        format!(
            "# Generated optional exact-artifact approvals; inert until explicitly installed.\n\
             # See FAIRGATE-FACTORY-SCAN.md for scope, exclusions, and review limitations.\n\n\
             {serialized_bundle}"
        ),
    )?;

    let scanned = results.len();
    let blocked_count = results.iter().filter(|result| result.blocked).count();
    let failures: Vec<_> = results
        .iter()
        .filter_map(|result| {
            result
                .error
                .as_ref()
                .map(|scan_error| (&result.artifact, scan_error))
        })
        .collect();
    let mut report = format!(
        "# Dependency Audit factory scan of Cargo Wrapper and FAIRGATE — 2026-09-04\n\n\
         This report records the inputs excluded from the optional embedded bundle. The scan used\n\
         exact registry metadata from {} `Cargo.lock` files found beneath {} `Cargo.toml` files in\n\
         {}. Archives were checksum-verified and parsed in bounded memory; no dependency source\n\
         was built or executed.\n\n\
         - Exact crates.io artifacts scanned: {scanned}\n\
         - Exact crates.io artifacts approved: {}\n\
         - Exact artifacts excluded by RustSec/yank status: {blocked_count}\n\
         - Strict archive scan failures: {}\n\
         - Non-crates.io remote artifacts excluded because the plugin cannot checksum-review them: {}\n\
         - Manifests without a lockfile in their directory or an ancestor: {}\n\n\
         A factory entry is not a claim that a crate is universally safe. It delegates only the\n\
         listed scanner findings for one source, name, version, checksum, and scanner version.\n\n",
        inventory.lockfile_count,
        inventory.manifest_count,
        source_roots
            .iter()
            .map(|root| format!("`{}`", project_root_name(Path::new(root))))
            .collect::<Vec<_>>()
            .join(" and "),
        bundle.approval_count(),
        failures.len(),
        inventory.unsupported_remote_artifacts.len(),
        inventory.unlocked_manifests.len(),
    );
    if !failures.is_empty() {
        report.push_str("## Strict scan failures (excluded)\n\n```text\n");
        for (artifact, scan_error) in failures {
            report.push_str(&format!(
                "{} {} {}: {}\n",
                artifact.name, artifact.version, artifact.checksum, scan_error
            ));
        }
        report.push_str("```\n\n");
    }
    if !inventory.unsupported_remote_artifacts.is_empty() {
        report.push_str("## Non-crates.io remote artifacts (excluded)\n\n```text\n");
        for (name, version, source) in &inventory.unsupported_remote_artifacts {
            report.push_str(&format!("{name} {version} {source}\n"));
        }
        report.push_str("```\n\n");
    }
    if !inventory.unlocked_manifests.is_empty() {
        report.push_str("## Manifests without an ancestor lockfile (not resolved)\n\n```text\n");
        for manifest in &inventory.unlocked_manifests {
            report.push_str(&format!(
                "{}\n",
                project_relative_path(manifest, source_roots)
            ));
        }
        report.push_str("```\n\n");
    }
    report.push_str("## RustSec, unmaintained, unsound, or yanked records (excluded)\n\n");
    report.push_str("Multiple advisory records can refer to the same exact artifact.\n\n```text\n");
    report.push_str("category\tadvisory\tcrate\tversion\tchecksum\n");
    report.push_str(&fs::read_to_string(blocked_path)?);
    report.push_str("```\n");
    fs::write(report_path, report)?;
    println!(
        "scanned={scanned} approved={} rustsec_excluded={blocked_count} failures={}",
        bundle.approval_count(),
        results
            .iter()
            .filter(|result| result.error.is_some())
            .count()
    );
    Ok(())
}

fn read_inventory(source_roots: &[String]) -> Result<Inventory> {
    let roots: Vec<_> = source_roots.iter().map(PathBuf::from).collect();
    let mut manifests = BTreeSet::new();
    let mut lockfiles = BTreeSet::new();
    for root in &roots {
        if !root.is_dir() {
            return Err(error(format!(
                "factory scan source root is not a directory: {}",
                root.display()
            )));
        }
        visit_project_files(root, &mut manifests, &mut lockfiles)?;
    }
    let lockfile_paths: BTreeSet<_> = lockfiles.iter().cloned().collect();
    let mut artifacts = BTreeSet::new();
    let mut unsupported_remote_artifacts = BTreeSet::new();
    for path in &lockfile_paths {
        let lockfile: Lockfile = toml::from_str(&fs::read_to_string(path)?)?;
        for package in lockfile.package {
            let Some(source) = package.source else {
                continue;
            };
            if source == CRATES_IO_SOURCE {
                let checksum = package.checksum.ok_or_else(|| {
                    error(format!(
                        "crates.io package {} {} has no checksum in {}",
                        package.name,
                        package.version,
                        path.display()
                    ))
                })?;
                artifacts.insert(Artifact {
                    name: package.name,
                    version: package.version,
                    source,
                    checksum,
                });
            } else {
                unsupported_remote_artifacts.insert((package.name, package.version, source));
            }
        }
    }
    let unlocked_manifests = manifests
        .iter()
        .filter(|manifest| {
            !roots.iter().any(|root| {
                manifest.starts_with(root) && has_ancestor_lock(manifest, root, &lockfile_paths)
            })
        })
        .cloned()
        .collect();
    Ok(Inventory {
        artifacts: artifacts.into_iter().collect(),
        manifest_count: manifests.len(),
        lockfile_count: lockfiles.len(),
        unlocked_manifests,
        unsupported_remote_artifacts: unsupported_remote_artifacts.into_iter().collect(),
    })
}

fn visit_project_files(
    directory: &Path,
    manifests: &mut BTreeSet<PathBuf>,
    lockfiles: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if matches!(
                entry.file_name().to_str(),
                Some(".git" | "target" | "vendor")
            ) {
                continue;
            }
            visit_project_files(&path, manifests, lockfiles)?;
        } else if file_type.is_file() {
            match entry.file_name().to_str() {
                Some("Cargo.toml") => {
                    manifests.insert(path);
                }
                Some("Cargo.lock") => {
                    lockfiles.insert(path);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn has_ancestor_lock(manifest: &Path, root: &Path, lockfiles: &BTreeSet<PathBuf>) -> bool {
    let mut directory = manifest.parent();
    while let Some(candidate) = directory {
        if lockfiles.contains(&candidate.join("Cargo.lock")) {
            return true;
        }
        if candidate == root {
            break;
        }
        directory = candidate.parent();
    }
    false
}

fn project_root_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source-root")
        .to_owned()
}

fn project_relative_path(path: &Path, source_roots: &[String]) -> String {
    for source_root in source_roots {
        let root = Path::new(source_root);
        if let Ok(relative) = path.strip_prefix(root) {
            return Path::new(&project_root_name(root))
                .join(relative)
                .display()
                .to_string();
        }
    }
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Cargo.toml".to_owned())
}

fn read_blocklist(path: &Path) -> Result<Arc<BTreeSet<(String, String, String)>>> {
    let mut blocked = BTreeSet::new();
    for line in fs::read_to_string(path)?.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() >= 5 {
            blocked.insert((
                fields[2].to_owned(),
                fields[3].to_owned(),
                fields[4].to_owned(),
            ));
        }
    }
    Ok(Arc::new(blocked))
}

fn cached_archives() -> Result<Arc<BTreeMap<String, PathBuf>>> {
    let Some(home) = std::env::var_os("HOME") else {
        return Ok(Arc::new(BTreeMap::new()));
    };
    let mut archives = BTreeMap::new();
    visit_files(
        &PathBuf::from(home).join(".cargo/registry/cache"),
        &mut |path| {
            if path
                .extension()
                .is_some_and(|extension| extension == "crate")
                && let Some(name) = path.file_name().and_then(|name| name.to_str())
            {
                archives
                    .entry(name.to_owned())
                    .or_insert_with(|| path.to_owned());
            }
        },
    )?;
    Ok(Arc::new(archives))
}

fn visit_files(directory: &Path, visitor: &mut dyn FnMut(&Path)) -> Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(read_error) if read_error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(read_error) => return Err(read_error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            visit_files(&entry.path(), visitor)?;
        } else if file_type.is_file() {
            visitor(&entry.path());
        }
    }
    Ok(())
}

fn download(agent: &ureq::Agent, artifact: &Artifact) -> Result<Vec<u8>> {
    let url = format!(
        "https://static.crates.io/crates/{0}/{0}-{1}.crate",
        artifact.name, artifact.version
    );
    let response = agent.get(&url).call().map_err(|download_error| {
        error(format!(
            "cannot download {} {}: {download_error}",
            artifact.name, artifact.version
        ))
    })?;
    if response
        .header("Content-Length")
        .and_then(|length| length.parse::<u64>().ok())
        .is_some_and(|length| length > MAX_ARCHIVE_BYTES)
    {
        return Err(error(format!(
            "archive exceeds {} byte limit",
            MAX_ARCHIVE_BYTES
        )));
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_ARCHIVE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(error(format!(
            "archive exceeds {} byte limit",
            MAX_ARCHIVE_BYTES
        )));
    }
    Ok(bytes)
}
