//! Verifies crate checksums and inspects bounded archives entirely in memory.
//! It identifies build-time entry points and delegates Rust text to the scanner.

use crate::findings::{Finding, ReviewSource};
use crate::scanner::{scan_rust_source, source_evidence};
use crate::{Result, error};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

const MAX_ENTRIES: usize = 4096;
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 4 * 1024 * 1024;

pub fn inspect_archive(bytes: &[u8], expected_checksum: &str) -> Result<BTreeSet<Finding>> {
    Ok(inspect_archive_for_review(bytes, expected_checksum)?.findings)
}

#[derive(Clone, Debug)]
pub struct ArchiveInspection {
    pub findings: BTreeSet<Finding>,
    pub sources: Vec<ReviewSource>,
}

pub fn inspect_archive_for_review(
    bytes: &[u8],
    expected_checksum: &str,
) -> Result<ArchiveInspection> {
    let received = format!("{:x}", Sha256::digest(bytes));
    if !received.eq_ignore_ascii_case(expected_checksum) {
        return Err(error(format!(
            "REGISTRY INTEGRITY FAILURE\n\nexpected: {expected_checksum}\nreceived: {received}\n\nABORTING."
        )));
    }

    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut files = BTreeMap::<PathBuf, Vec<u8>>::new();
    let mut archive_root = None;
    let mut count = 0usize;
    let mut total = 0u64;
    for entry in archive.entries()? {
        let entry = entry?;
        count += 1;
        if count > MAX_ENTRIES {
            return Err(error(format!(
                "crate archive exceeds {MAX_ENTRIES} entry limit"
            )));
        }
        let path = entry.path()?.into_owned();
        validate_archive_path(&path)?;
        let root = path
            .components()
            .next()
            .and_then(|component| match component {
                Component::Normal(name) => Some(name.to_owned()),
                _ => None,
            })
            .ok_or_else(|| error("invalid crate archive root"))?;
        if archive_root
            .as_ref()
            .is_some_and(|expected| expected != &root)
        {
            return Err(error("crate archive contains multiple top-level roots"));
        }
        archive_root.get_or_insert(root);
        let size = entry.size();
        total = total
            .checked_add(size)
            .ok_or_else(|| error("crate archive declared size overflow"))?;
        if total > MAX_DECOMPRESSED_BYTES {
            return Err(error(format!(
                "crate archive exceeds {MAX_DECOMPRESSED_BYTES} decompressed byte limit"
            )));
        }
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        let relative = strip_archive_root(&path)?;
        let relevant = relative == Path::new("Cargo.toml")
            || relative == Path::new("Cargo.toml.orig")
            || relative
                .extension()
                .is_some_and(|extension| extension == "rs");
        if !relevant {
            continue;
        }
        if size > MAX_ENTRY_BYTES {
            return Err(error(format!(
                "relevant archive entry {} exceeds {MAX_ENTRY_BYTES} byte limit",
                relative.display()
            )));
        }
        let mut contents = Vec::with_capacity(size.min(64 * 1024) as usize);
        entry.take(MAX_ENTRY_BYTES + 1).read_to_end(&mut contents)?;
        if contents.len() as u64 > MAX_ENTRY_BYTES {
            return Err(error(
                "archive entry expanded beyond declared inspection limit",
            ));
        }
        files.insert(relative, contents);
    }

    inspect_files(&files)
}

fn inspect_files(files: &BTreeMap<PathBuf, Vec<u8>>) -> Result<ArchiveInspection> {
    let manifest_bytes = files
        .get(Path::new("Cargo.toml"))
        .ok_or_else(|| error("crate archive has no normalized Cargo.toml"))?;
    let manifest_text = std::str::from_utf8(manifest_bytes)?;
    let manifest: toml::Value = toml::from_str(manifest_text)?;
    let build_script = active_build_script(&manifest, files);
    let proc_macro = manifest
        .get("lib")
        .and_then(|lib| lib.get("proc-macro"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    let mut findings = BTreeSet::new();
    let mut relevant_paths = BTreeSet::from([PathBuf::from("Cargo.toml")]);
    if let Some(path) = &build_script {
        findings.insert(
            Finding::new(
                "build-script",
                format!("active Cargo custom build target: {}", path.display()),
            )
            .with_evidence(source_evidence(
                manifest_text,
                manifest_text,
                "Cargo.toml",
                &[path.to_string_lossy().as_ref(), "build"],
            )),
        );
        relevant_paths.insert(path.clone());
    }
    for dependency in build_dependency_names(&manifest) {
        findings.insert(
            Finding::new(
                "build-dependencies",
                format!("manifest build dependency: {dependency}"),
            )
            .with_evidence(source_evidence(
                manifest_text,
                manifest_text,
                "Cargo.toml",
                &[&dependency, "build-dependencies"],
            )),
        );
    }
    if proc_macro {
        findings.insert(
            Finding::new(
                "proc-macro",
                "crate manifest declares [lib] proc-macro = true",
            )
            .with_evidence(source_evidence(
                manifest_text,
                manifest_text,
                "Cargo.toml",
                &["proc-macro"],
            )),
        );
        if let Some(path) = proc_macro_source(&manifest, files) {
            relevant_paths.insert(path);
        }
    }

    if build_script.is_some() || proc_macro {
        for (path, bytes) in files {
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let source = String::from_utf8_lossy(bytes);
            let primary = build_script.as_ref().is_some_and(|script| script == path);
            let context = if primary {
                path.display().to_string()
            } else {
                format!("potential build-time helper {}", path.display())
            };
            let file_findings = scan_rust_source(&source, &context);
            if !file_findings.is_empty() {
                relevant_paths.insert(path.clone());
            }
            findings.extend(file_findings);
        }
    }
    let sources = relevant_paths
        .into_iter()
        .filter_map(|path| {
            files.get(&path).map(|bytes| ReviewSource {
                path: path.display().to_string(),
                contents: String::from_utf8_lossy(bytes).into_owned(),
            })
        })
        .collect();
    Ok(ArchiveInspection { findings, sources })
}

fn proc_macro_source(
    manifest: &toml::Value,
    files: &BTreeMap<PathBuf, Vec<u8>>,
) -> Option<PathBuf> {
    let configured = manifest
        .get("lib")
        .and_then(|lib| lib.get("path"))
        .and_then(toml::Value::as_str)
        .map(PathBuf::from);
    configured.or_else(|| {
        files
            .contains_key(Path::new("src/lib.rs"))
            .then(|| PathBuf::from("src/lib.rs"))
    })
}

fn active_build_script(
    manifest: &toml::Value,
    files: &BTreeMap<PathBuf, Vec<u8>>,
) -> Option<PathBuf> {
    match manifest
        .get("package")
        .and_then(|package| package.get("build"))
    {
        Some(toml::Value::Boolean(false)) => None,
        Some(toml::Value::String(path)) => Some(PathBuf::from(path)),
        _ if files.contains_key(Path::new("build.rs")) => Some(PathBuf::from("build.rs")),
        _ => None,
    }
}

fn build_dependency_names(manifest: &toml::Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Some(table) = manifest
        .get("build-dependencies")
        .and_then(toml::Value::as_table)
    {
        names.extend(table.keys().cloned());
    }
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            if let Some(table) = target
                .get("build-dependencies")
                .and_then(toml::Value::as_table)
            {
                names.extend(table.keys().cloned());
            }
        }
    }
    names
}

fn validate_archive_path(path: &Path) -> Result<()> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(error(format!(
            "unsafe crate archive path: {}",
            path.display()
        )));
    }
    Ok(())
}

fn strip_archive_root(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let root = components
        .next()
        .ok_or_else(|| error("empty crate archive path"))?;
    if !matches!(root, Component::Normal(_)) {
        return Err(error("invalid crate archive root"));
    }
    Ok(components.collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn crate_archive(manifest: &str, source_files: &[(&str, &str)]) -> (Vec<u8>, String) {
        let mut compressed = Vec::new();
        {
            let encoder = GzEncoder::new(&mut compressed, Compression::default());
            let mut builder = tar::Builder::new(encoder);
            append(&mut builder, "demo-1.0.0/Cargo.toml", manifest.as_bytes());
            for (path, contents) in source_files {
                append(
                    &mut builder,
                    &format!("demo-1.0.0/{path}"),
                    contents.as_bytes(),
                );
            }
            builder.into_inner().unwrap().finish().unwrap();
        }
        let checksum = format!("{:x}", Sha256::digest(&compressed));
        (compressed, checksum)
    }

    fn append<W: std::io::Write>(builder: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }

    #[test]
    fn finds_active_custom_build_script_and_capabilities_without_extracting() {
        let manifest = "[package]\nname='demo'\nversion='1.0.0'\nbuild='tools/make.rs'\n[build-dependencies]\ncc='1'";
        let (bytes, checksum) = crate_archive(
            manifest,
            &[(
                "tools/make.rs",
                "fn main(){std::process::Command::new(\"sh\").status();}",
            )],
        );
        let findings = inspect_archive(&bytes, &checksum).unwrap();
        let capabilities: BTreeSet<_> = findings
            .iter()
            .map(|finding| finding.capability.as_str())
            .collect();
        assert!(capabilities.contains("build-script"));
        assert!(capabilities.contains("build-dependencies"));
        assert!(capabilities.contains("process-execution"));
        assert!(capabilities.contains("shell-or-downloader"));

        let inspection = inspect_archive_for_review(&bytes, &checksum).unwrap();
        let process = inspection
            .findings
            .iter()
            .find(|finding| finding.capability == "process-execution")
            .unwrap();
        assert_eq!(process.evidence[0].path, "tools/make.rs");
        assert_eq!(process.evidence[0].focus_line, 1);
        assert!(
            inspection
                .sources
                .iter()
                .any(|source| source.path == "Cargo.toml")
        );
        assert!(inspection.sources.iter().any(|source| {
            source.path == "tools/make.rs" && source.contents.contains("Command::new")
        }));
    }

    #[test]
    fn build_false_disables_implicit_build_rs() {
        let manifest = "[package]\nname='demo'\nversion='1.0.0'\nbuild=false";
        let (bytes, checksum) = crate_archive(
            manifest,
            &[("build.rs", "std::process::Command::new(\"sh\");")],
        );
        assert!(inspect_archive(&bytes, &checksum).unwrap().is_empty());
    }

    #[test]
    fn checksum_mismatch_is_not_overridable() {
        let (bytes, _) = crate_archive("[package]\nname='demo'\nversion='1.0.0'", &[]);
        let error = inspect_archive(&bytes, "0000").unwrap_err().to_string();
        assert!(error.contains("REGISTRY INTEGRITY FAILURE"));
    }

    #[test]
    fn proc_macro_is_an_inherent_build_time_finding() {
        let manifest = "[package]\nname='demo'\nversion='1.0.0'\nbuild=false\n[lib]\nproc-macro=true\npath='src/lib.rs'";
        let (bytes, checksum) =
            crate_archive(manifest, &[("src/lib.rs", "extern crate proc_macro;")]);
        let findings = inspect_archive(&bytes, &checksum).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.capability == "proc-macro")
        );
        let inspection = inspect_archive_for_review(&bytes, &checksum).unwrap();
        assert!(
            inspection
                .sources
                .iter()
                .any(|source| source.path == "src/lib.rs")
        );
    }
}
