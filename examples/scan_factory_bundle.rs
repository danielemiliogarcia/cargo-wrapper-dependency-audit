//! Maintainer tool that statically scans exact crates.io artifacts from lockfile inventory.
//! It verifies archive checksums, never extracts source, and excludes RustSec-flagged entries.

use cargo_wrapper_dependency_audit::archive_inspector::inspect_archive;
use cargo_wrapper_dependency_audit::factory_approvals::{FactoryApproval, FactoryBundle};
use cargo_wrapper_dependency_audit::registry::MAX_ARCHIVE_BYTES;
use cargo_wrapper_dependency_audit::scanner::SCANNER_VERSION;
use cargo_wrapper_dependency_audit::{Result, error};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const DOWNLOAD_ATTEMPTS: usize = 4;
const DOWNLOAD_RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
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
    previous_approval_count: usize,
    previous_only_approval_count: usize,
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
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--write-bundle-lock")
    {
        if arguments.len() != 3 {
            return Err(error(
                "usage: cargo run --example scan_factory_bundle -- --write-bundle-lock <bundle.toml> <output.lock>",
            ));
        }
        return write_bundle_lock(Path::new(&arguments[1]), Path::new(&arguments[2]));
    }
    let existing_bundle = if arguments
        .first()
        .is_some_and(|argument| argument == "--existing-bundle")
    {
        if arguments.len() < 6 {
            return Err(error(
                "--existing-bundle requires a path followed by source roots and the three output arguments",
            ));
        }
        let path = PathBuf::from(&arguments[1]);
        arguments.drain(..2);
        Some(path)
    } else {
        None
    };
    if arguments.len() < 4 {
        return Err(error(
            "usage: cargo run --example scan_factory_bundle -- [--existing-bundle <bundle.toml>] <source-root>... <rustsec-blocklist> <output.toml> <report.md>",
        ));
    }
    let output_arguments = arguments.len() - 3;
    let source_roots = &arguments[..output_arguments];
    let blocked_path = &arguments[output_arguments];
    let output_path = &arguments[output_arguments + 1];
    let report_path = &arguments[output_arguments + 2];

    let inventory = read_inventory(source_roots, existing_bundle.as_deref())?;
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
    ensure_scans_succeeded(&results)?;

    let approvals = results
        .iter()
        .filter(|result| !result.blocked)
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
    let reviewed_at = utc_date();
    let bundle = FactoryBundle::from_approvals(
        format!("{reviewed_at}-factory"),
        reviewed_at,
        "Exact crates.io artifacts locked by the selected source projects, checksum-verified and statically scanned by Dependency Audit; RustSec-flagged artifacts excluded".to_owned(),
        approvals,
    )?;
    let serialized_bundle = toml::to_string_pretty(&bundle)?;
    fs::write(
        output_path,
        format!(
            "# Generated optional exact-artifact approvals; inert until explicitly installed.\n\
             # See FACTORY-SCAN.md for cumulative scope, exclusions, and review limitations.\n\n\
             {serialized_bundle}"
        ),
    )?;

    let scanned = results.len();
    let blocked_count = results.iter().filter(|result| result.blocked).count();
    let mut report = format!(
        "## Scan for bundle `{}` (reviewed {})\n\n\
         This report records the inputs excluded from the optional embedded bundle. The scan used\n\
         exact registry metadata from {} `Cargo.lock` files found beneath {} `Cargo.toml` files in\n\
         {}. Archives were checksum-verified and parsed in bounded memory; no dependency source\n\
         was built or executed.\n\n\
         - Exact crates.io artifacts scanned: {scanned}\n\
         - Exact identities loaded from the previous bundle: {}\n\
         - Previous identities not present in current lockfiles: {}\n\
         - Exact crates.io artifacts approved: {}\n\
         - Exact artifacts excluded by RustSec/yank status: {blocked_count}\n\
         - Strict archive scan failures: 0 (any failure aborts generation)\n\
         - Non-crates.io remote artifacts excluded because the plugin cannot checksum-review them: {}\n\
         - Manifests without a lockfile in their directory or an ancestor: {}\n\n\
         A factory entry is not a claim that a crate is universally safe. It delegates only the\n\
         listed scanner findings for one source, name, version, checksum, and scanner version.\n\n",
        bundle.bundle_version,
        bundle.reviewed_at,
        inventory.lockfile_count,
        inventory.manifest_count,
        source_roots
            .iter()
            .map(|root| format!("`{}`", project_root_name(Path::new(root))))
            .collect::<Vec<_>>()
            .join(" and "),
        inventory.previous_approval_count,
        inventory.previous_only_approval_count,
        bundle.approval_count(),
        inventory.unsupported_remote_artifacts.len(),
        inventory.unlocked_manifests.len(),
    );
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
    append_report(Path::new(report_path), &report)?;
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

fn append_report(path: &Path, report: &str) -> Result<()> {
    let needs_header = match fs::metadata(path) {
        Ok(metadata) => metadata.len() == 0,
        Err(read_error) if read_error.kind() == std::io::ErrorKind::NotFound => true,
        Err(read_error) => return Err(read_error.into()),
    };
    let mut output = OpenOptions::new().create(true).append(true).open(path)?;
    if needs_header {
        output.write_all(b"# Dependency Audit factory scan history\n\n")?;
    } else {
        output.write_all(b"\n---\n\n")?;
    }
    output.write_all(report.as_bytes())?;
    Ok(())
}

fn utc_date() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_utc_date(now.as_secs())
}

fn format_utc_date(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let shifted_days = days + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn read_inventory(source_roots: &[String], existing_bundle: Option<&Path>) -> Result<Inventory> {
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
    let (previous_approval_count, previous_only_approval_count) =
        if let Some(path) = existing_bundle {
            let bundle = read_bundle(path)?;
            let previous_approval_count = bundle.approval_count();
            let mut previous_only_approval_count = 0;
            for approval in bundle.approvals() {
                if artifacts.insert(Artifact {
                    name: approval.name,
                    version: approval.version,
                    source: approval.source,
                    checksum: approval.checksum,
                }) {
                    previous_only_approval_count += 1;
                }
            }
            (previous_approval_count, previous_only_approval_count)
        } else {
            (0, 0)
        };
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
        previous_approval_count,
        previous_only_approval_count,
        manifest_count: manifests.len(),
        lockfile_count: lockfiles.len(),
        unlocked_manifests,
        unsupported_remote_artifacts: unsupported_remote_artifacts.into_iter().collect(),
    })
}

fn read_bundle(path: &Path) -> Result<FactoryBundle> {
    let contents = fs::read_to_string(path)?;
    let bundle: FactoryBundle = toml::from_str(&contents)?;
    bundle.validate()?;
    Ok(bundle)
}

#[derive(Serialize)]
struct AuditLockfile {
    version: u32,
    package: Vec<AuditLockPackage>,
}

#[derive(Serialize)]
struct AuditLockPackage {
    name: String,
    version: String,
    source: String,
    checksum: String,
}

fn write_bundle_lock(bundle_path: &Path, output_path: &Path) -> Result<()> {
    let bundle = read_bundle(bundle_path)?;
    let mut package: Vec<_> = bundle
        .approvals()
        .map(|approval| AuditLockPackage {
            name: approval.name,
            version: approval.version,
            source: approval.source,
            checksum: approval.checksum,
        })
        .collect();
    package.sort_by(|left, right| {
        (&left.name, &left.version, &left.checksum).cmp(&(
            &right.name,
            &right.version,
            &right.checksum,
        ))
    });
    let lockfile = AuditLockfile {
        version: 4,
        package,
    };
    fs::write(output_path, toml::to_string_pretty(&lockfile)?)?;
    println!(
        "wrote {} exact prior approvals to {} for current RustSec evaluation",
        lockfile.package.len(),
        output_path.display()
    );
    Ok(())
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
    download_url_with_retry(agent, artifact, &url, DOWNLOAD_ATTEMPTS, thread::sleep)
}

#[derive(Debug)]
struct DownloadAttemptError {
    message: String,
    transient: bool,
}

fn download_url_with_retry(
    agent: &ureq::Agent,
    artifact: &Artifact,
    url: &str,
    attempts: usize,
    mut wait: impl FnMut(Duration),
) -> Result<Vec<u8>> {
    assert!(attempts > 0, "download attempts must be nonzero");
    for attempt in 1..=attempts {
        match download_once(agent, url) {
            Ok(bytes) => return Ok(bytes),
            Err(download_error) if download_error.transient && attempt < attempts => {
                let delay = DOWNLOAD_RETRY_BASE_DELAY * (1 << (attempt - 1));
                eprintln!(
                    "temporary download failure for {} {} (attempt {attempt}/{attempts}): {}; retrying in {} ms",
                    artifact.name,
                    artifact.version,
                    download_error.message,
                    delay.as_millis()
                );
                wait(delay);
            }
            Err(download_error) => {
                let attempts_description = if download_error.transient {
                    format!(" after {attempt} attempts")
                } else {
                    String::new()
                };
                return Err(error(format!(
                    "cannot download {} {}{attempts_description}: {url}: {}",
                    artifact.name, artifact.version, download_error.message
                )));
            }
        }
    }
    unreachable!("a nonzero download attempt count always returns")
}

fn download_once(
    agent: &ureq::Agent,
    url: &str,
) -> std::result::Result<Vec<u8>, DownloadAttemptError> {
    let response = match agent.get(url).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(status, _)) => {
            return Err(DownloadAttemptError {
                message: format!("status code {status}"),
                transient: status == 408 || status == 429 || (500..=599).contains(&status),
            });
        }
        Err(ureq::Error::Transport(transport_error)) => {
            return Err(DownloadAttemptError {
                message: transport_error.to_string(),
                transient: true,
            });
        }
    };
    if response
        .header("Content-Length")
        .and_then(|length| length.parse::<u64>().ok())
        .is_some_and(|length| length > MAX_ARCHIVE_BYTES)
    {
        return Err(DownloadAttemptError {
            message: format!("archive exceeds {MAX_ARCHIVE_BYTES} byte limit"),
            transient: false,
        });
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_ARCHIVE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|read_error| DownloadAttemptError {
            message: format!("cannot read response body: {read_error}"),
            transient: true,
        })?;
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(DownloadAttemptError {
            message: format!("archive exceeds {MAX_ARCHIVE_BYTES} byte limit"),
            transient: false,
        });
    }
    Ok(bytes)
}

fn ensure_scans_succeeded(results: &[ScanResult]) -> Result<()> {
    let failures: Vec<_> = results
        .iter()
        .filter_map(|result| {
            result
                .error
                .as_ref()
                .map(|scan_error| (&result.artifact, scan_error))
        })
        .collect();
    if failures.is_empty() {
        return Ok(());
    }

    let mut message = format!(
        "factory scan aborted after {} archive failure(s); existing factory bundle and report were not modified",
        failures.len()
    );
    for (artifact, scan_error) in failures {
        message.push_str(&format!(
            "\n- {} {} {}: {}",
            artifact.name, artifact.version, artifact.checksum, scan_error
        ));
    }
    Err(error(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn approval(name: &str, version: &str, checksum_byte: char) -> FactoryApproval {
        FactoryApproval {
            source: CRATES_IO_SOURCE.to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
            checksum: checksum_byte.to_string().repeat(64),
            scanner_version: SCANNER_VERSION,
            approved_findings: BTreeSet::from(["build-time-closure".to_owned()]),
        }
    }

    fn write_bundle(path: &Path, approvals: Vec<FactoryApproval>) {
        let bundle = FactoryBundle::from_approvals(
            "test-bundle".to_owned(),
            "2026-09-07".to_owned(),
            "test fixture".to_owned(),
            approvals,
        )
        .unwrap();
        fs::write(path, toml::to_string_pretty(&bundle).unwrap()).unwrap();
    }

    fn write_source_lock(root: &Path) {
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"current-crate\"\nversion = \"2.0.0\"\nsource = \"{CRATES_IO_SOURCE}\"\nchecksum = \"{}\"\n",
                "b".repeat(64)
            ),
        )
        .unwrap();
    }

    fn serve_statuses(
        statuses: Vec<u16>,
        success_body: &'static [u8],
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for status in statuses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).unwrap();
                let (reason, body) = if status == 200 {
                    ("OK", success_body)
                } else {
                    ("temporary failure", &b"failure"[..])
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        });
        (format!("http://{address}/archive.crate"), handle)
    }

    fn download_artifact() -> Artifact {
        Artifact {
            name: "fixture-crate".to_owned(),
            version: "1.0.0".to_owned(),
            source: CRATES_IO_SOURCE.to_owned(),
            checksum: "a".repeat(64),
        }
    }

    #[test]
    fn append_inventory_unions_previous_exact_approvals_with_current_locks() {
        let directory = tempfile::tempdir().unwrap();
        let source_root = directory.path().join("source");
        fs::create_dir(&source_root).unwrap();
        write_source_lock(&source_root);
        let bundle_path = directory.path().join("factory-approvals.toml");
        write_bundle(&bundle_path, vec![approval("previous-crate", "1.0.0", 'a')]);

        let inventory = read_inventory(
            &[source_root.display().to_string()],
            Some(bundle_path.as_path()),
        )
        .unwrap();

        assert_eq!(inventory.previous_approval_count, 1);
        assert_eq!(inventory.previous_only_approval_count, 1);
        assert_eq!(inventory.artifacts.len(), 2);
        assert!(
            inventory
                .artifacts
                .iter()
                .any(|artifact| artifact.name == "previous-crate")
        );
        assert!(
            inventory
                .artifacts
                .iter()
                .any(|artifact| artifact.name == "current-crate")
        );
    }

    #[test]
    fn reset_inventory_uses_only_current_locks() {
        let directory = tempfile::tempdir().unwrap();
        let source_root = directory.path().join("source");
        fs::create_dir(&source_root).unwrap();
        write_source_lock(&source_root);

        let inventory = read_inventory(&[source_root.display().to_string()], None).unwrap();

        assert_eq!(inventory.previous_approval_count, 0);
        assert_eq!(inventory.previous_only_approval_count, 0);
        assert_eq!(inventory.artifacts.len(), 1);
        assert_eq!(inventory.artifacts[0].name, "current-crate");
    }

    #[test]
    fn prior_bundle_is_written_as_an_auditable_lockfile() {
        let directory = tempfile::tempdir().unwrap();
        let bundle_path = directory.path().join("factory-approvals.toml");
        let lock_path = directory.path().join("previous.lock");
        write_bundle(
            &bundle_path,
            vec![
                approval("second-crate", "2.0.0", '2'),
                approval("first-crate", "1.0.0", '1'),
            ],
        );

        write_bundle_lock(&bundle_path, &lock_path).unwrap();

        let lockfile: Lockfile = toml::from_str(&fs::read_to_string(lock_path).unwrap()).unwrap();
        assert_eq!(lockfile.package.len(), 2);
        assert_eq!(lockfile.package[0].name, "first-crate");
        assert_eq!(lockfile.package[0].version, "1.0.0");
        assert_eq!(
            lockfile.package[0].source.as_deref(),
            Some(CRATES_IO_SOURCE)
        );
        assert_eq!(
            lockfile.package[0].checksum.as_deref(),
            Some(&*"1".repeat(64))
        );
        assert_eq!(lockfile.package[1].name, "second-crate");
    }

    #[test]
    fn scan_reports_append_without_erasing_history() {
        let directory = tempfile::tempdir().unwrap();
        let report_path = directory.path().join("FACTORY-SCAN.md");

        append_report(&report_path, "## First scan\n").unwrap();
        append_report(&report_path, "## Second scan\n").unwrap();

        let report = fs::read_to_string(report_path).unwrap();
        assert!(report.starts_with("# Dependency Audit factory scan history\n"));
        assert_eq!(report.matches("## First scan").count(), 1);
        assert_eq!(report.matches("## Second scan").count(), 1);
        assert!(report.contains("\n---\n"));
    }

    #[test]
    fn factory_dates_are_formatted_in_utc_without_external_tools() {
        assert_eq!(format_utc_date(0), "1970-01-01");
        assert_eq!(format_utc_date(1_735_689_599), "2024-12-31");
    }

    #[test]
    fn transient_download_failures_are_retried_with_bounded_backoff() {
        let (url, server) = serve_statuses(vec![500, 502, 200], b"crate bytes");
        let agent = ureq::AgentBuilder::new().build();
        let mut waits = Vec::new();

        let bytes = download_url_with_retry(&agent, &download_artifact(), &url, 4, |delay| {
            waits.push(delay);
        })
        .unwrap();

        assert_eq!(bytes, b"crate bytes");
        assert_eq!(
            waits,
            vec![Duration::from_millis(250), Duration::from_millis(500)]
        );
        server.join().unwrap();
    }

    #[test]
    fn permanent_download_failures_are_not_retried() {
        let (url, server) = serve_statuses(vec![404], b"");
        let agent = ureq::AgentBuilder::new().build();
        let mut waits = 0;

        let failure = download_url_with_retry(&agent, &download_artifact(), &url, 4, |_| {
            waits += 1;
        })
        .unwrap_err()
        .to_string();

        assert_eq!(waits, 0);
        assert!(failure.contains("status code 404"));
        server.join().unwrap();
    }

    #[test]
    fn exhausted_transient_downloads_fail_the_scan() {
        let (url, server) = serve_statuses(vec![500, 500, 500, 500], b"");
        let agent = ureq::AgentBuilder::new().build();
        let mut waits = Vec::new();

        let download_failure =
            download_url_with_retry(&agent, &download_artifact(), &url, 4, |delay| {
                waits.push(delay);
            })
            .unwrap_err()
            .to_string();
        server.join().unwrap();
        assert!(download_failure.contains("after 4 attempts"));
        assert_eq!(waits.len(), 3);

        let artifact = download_artifact();
        let scan_failure = ensure_scans_succeeded(&[ScanResult {
            artifact,
            findings: BTreeSet::new(),
            error: Some(download_failure),
            blocked: false,
        }])
        .unwrap_err()
        .to_string();
        assert!(scan_failure.contains("factory scan aborted after 1 archive failure"));
        assert!(scan_failure.contains("were not modified"));
    }
}
