//! Fetches bounded sparse-registry metadata and verified crate archives.
//! It derives pre-download findings from dependency metadata and build-time closure.

use crate::findings::{ArtifactId, Finding};
use crate::lockfile::{CargoLock, LockPackage};
use crate::{Result, error};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Read;
use std::time::Duration;

pub const MAX_ARCHIVE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
pub struct IndexDependency {
    pub name: String,
    pub req: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub package: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IndexVersion {
    pub name: String,
    pub vers: String,
    pub deps: Vec<IndexDependency>,
    pub cksum: String,
    #[serde(default)]
    pub yanked: bool,
}

pub trait RegistryClient {
    fn index_version(&self, artifact: &ArtifactId) -> Result<IndexVersion>;
    fn download_archive(&self, artifact: &ArtifactId) -> Result<Vec<u8>>;
}

pub struct HttpRegistryClient {
    agent: ureq::Agent,
}

impl Default for HttpRegistryClient {
    fn default() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout_read(Duration::from_secs(30))
                .timeout_write(Duration::from_secs(10))
                .redirects(5)
                .build(),
        }
    }
}

impl HttpRegistryClient {
    fn registry_base(source: &str) -> Result<String> {
        match source {
            "registry+https://github.com/rust-lang/crates.io-index" => {
                Ok("https://index.crates.io".to_owned())
            }
            value if value.starts_with("sparse+") => Ok(value
                .trim_start_matches("sparse+")
                .trim_end_matches('/')
                .to_owned()),
            value
                if value.starts_with("registry+http://")
                    || value.starts_with("registry+https://") =>
            {
                Ok(value
                    .trim_start_matches("registry+")
                    .trim_end_matches('/')
                    .to_owned())
            }
            _ => Err(error(format!(
                "dependency-audit: registry source is not a supported sparse registry: {source}"
            ))),
        }
    }

    fn get_bounded(&self, url: &str, maximum: u64) -> Result<Vec<u8>> {
        let response = self.agent.get(url).call().map_err(|request_error| {
            error(format!(
                "registry request failed for {url}: {request_error}"
            ))
        })?;
        if let Some(length) = response.header("Content-Length")
            && length.parse::<u64>().unwrap_or(maximum + 1) > maximum
        {
            return Err(error(format!(
                "registry response exceeds {maximum} byte limit"
            )));
        }
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(maximum + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            return Err(error(format!(
                "registry response exceeds {maximum} byte limit"
            )));
        }
        Ok(bytes)
    }

    fn config(&self, base: &str) -> Result<RegistryConfig> {
        let bytes = self.get_bounded(&format!("{base}/config.json"), 1024 * 1024)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

impl RegistryClient for HttpRegistryClient {
    fn index_version(&self, artifact: &ArtifactId) -> Result<IndexVersion> {
        let base = Self::registry_base(&artifact.source)?;
        let path = sparse_index_path(&artifact.name);
        let bytes = self.get_bounded(&format!("{base}/{path}"), MAX_INDEX_BYTES)?;
        let text = std::str::from_utf8(&bytes)?;
        let version = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(serde_json::from_str::<IndexVersion>)
            .find_map(|result| match result {
                Ok(entry) if entry.vers == artifact.version => Some(Ok(entry)),
                Ok(_) => None,
                Err(parse_error) => Some(Err(parse_error)),
            })
            .transpose()?
            .ok_or_else(|| {
                error(format!(
                    "registry index has no {} {} entry",
                    artifact.name, artifact.version
                ))
            })?;
        if version.name != artifact.name || version.cksum != artifact.checksum {
            return Err(error(format!(
                "REGISTRY INTEGRITY FAILURE\n\ncrate: {} {}\nlock checksum: {}\nindex checksum: {}\n\nABORTING.",
                artifact.name, artifact.version, artifact.checksum, version.cksum
            )));
        }
        Ok(version)
    }

    fn download_archive(&self, artifact: &ArtifactId) -> Result<Vec<u8>> {
        let base = Self::registry_base(&artifact.source)?;
        let config = self.config(&base)?;
        let index_path = sparse_index_path(&artifact.name);
        let prefix = index_path
            .rsplit_once('/')
            .map(|(prefix, _)| prefix)
            .unwrap_or("");
        let url = config
            .dl
            .replace("{crate}", &artifact.name)
            .replace("{version}", &artifact.version)
            .replace("{prefix}", prefix)
            .replace("{lowerprefix}", &prefix.to_ascii_lowercase())
            .replace("{sha256-checksum}", &artifact.checksum);
        let url = if url.contains('{') {
            return Err(error(format!(
                "unsupported registry download template: {}",
                config.dl
            )));
        } else if config.dl.contains("{crate}") || config.dl.ends_with(".crate") {
            url
        } else {
            format!(
                "{}/{}/{}/download",
                config.dl.trim_end_matches('/'),
                artifact.name,
                artifact.version
            )
        };
        self.get_bounded(&url, MAX_ARCHIVE_BYTES)
    }
}

#[derive(Deserialize)]
struct RegistryConfig {
    dl: String,
}

pub fn sparse_index_path(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

pub fn load_index_metadata(
    lock: &CargoLock,
    client: &dyn RegistryClient,
) -> Result<BTreeMap<ArtifactId, IndexVersion>> {
    let mut result = BTreeMap::new();
    for artifact in lock.remote_artifacts()? {
        result.insert(artifact.clone(), client.index_version(&artifact)?);
    }
    Ok(result)
}

pub fn stage_one_findings(
    lock: &CargoLock,
    metadata: &BTreeMap<ArtifactId, IndexVersion>,
    local_build_dependencies: &BTreeSet<String>,
) -> BTreeMap<ArtifactId, BTreeSet<Finding>> {
    const SUSPICIOUS: &[&str] = &[
        "reqwest",
        "ureq",
        "hyper",
        "rustls",
        "native-tls",
        "curl",
        "isahc",
        "attohttpc",
    ];
    let packages = lock.package.as_deref().unwrap_or_default();
    let artifact_by_package: BTreeMap<(&str, &str, &str), &ArtifactId> = metadata
        .keys()
        .map(|artifact| {
            (
                (
                    artifact.name.as_str(),
                    artifact.version.as_str(),
                    artifact.source.as_str(),
                ),
                artifact,
            )
        })
        .collect();
    let mut findings: BTreeMap<ArtifactId, BTreeSet<Finding>> = BTreeMap::new();
    let mut queue = VecDeque::new();

    for dependency in local_build_dependencies {
        queue.extend(
            packages
                .iter()
                .filter(|package| package.name == *dependency),
        );
    }

    for (artifact, entry) in metadata {
        for dependency in entry
            .deps
            .iter()
            .filter(|dependency| dependency.kind.as_deref() == Some("build"))
        {
            findings
                .entry(artifact.clone())
                .or_default()
                .insert(Finding::new(
                    "build-dependencies",
                    format!(
                        "build dependency: {} {}",
                        dependency.package.as_deref().unwrap_or(&dependency.name),
                        dependency.req
                    ),
                ));
            for target in matching_packages(packages, dependency) {
                queue.push_back(target);
            }
        }
        if entry.yanked {
            findings
                .entry(artifact.clone())
                .or_default()
                .insert(Finding::new(
                    "yanked-version",
                    "registry index marks this exact version as yanked",
                ));
        }
    }

    let mut visited = BTreeSet::new();
    while let Some(package) = queue.pop_front() {
        let key = (
            package.name.as_str(),
            package.version.as_str(),
            package.source.as_deref().unwrap_or(""),
        );
        if !visited.insert((key.0.to_owned(), key.1.to_owned(), key.2.to_owned())) {
            continue;
        }
        if let Some(artifact) = artifact_by_package.get(&key) {
            findings
                .entry((*artifact).clone())
                .or_default()
                .insert(Finding::new(
                    "build-time-closure",
                    "reachable from a build-dependency edge",
                ));
            if SUSPICIOUS.contains(&package.name.as_str()) {
                findings
                    .entry((*artifact).clone())
                    .or_default()
                    .insert(Finding::new(
                        "build-time-network-family",
                        format!(
                            "network/process-heavy package `{}` is in the build-time closure",
                            package.name
                        ),
                    ));
            }
        }
        for dependency in &package.dependencies {
            queue.extend(resolve_lock_dependency(packages, dependency));
        }
    }
    findings
}

fn matching_packages<'a>(
    packages: &'a [LockPackage],
    dependency: &IndexDependency,
) -> Vec<&'a LockPackage> {
    let actual_name = dependency.package.as_deref().unwrap_or(&dependency.name);
    let requirement = VersionReq::parse(&dependency.req).ok();
    packages
        .iter()
        .filter(|package| package.name == actual_name)
        .filter(|package| {
            requirement
                .as_ref()
                .and_then(|requirement| {
                    Version::parse(&package.version)
                        .ok()
                        .map(|version| requirement.matches(&version))
                })
                .unwrap_or(true)
        })
        .collect()
}

fn resolve_lock_dependency<'a>(
    packages: &'a [LockPackage],
    dependency: &str,
) -> Vec<&'a LockPackage> {
    let mut parts = dependency.split_whitespace();
    let Some(name) = parts.next() else {
        return Vec::new();
    };
    let version = parts
        .next()
        .filter(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()));
    packages
        .iter()
        .filter(|package| {
            package.name == name && version.is_none_or(|version| package.version == version)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_paths_follow_cargo_layout() {
        assert_eq!(sparse_index_path("a"), "1/a");
        assert_eq!(sparse_index_path("ab"), "2/ab");
        assert_eq!(sparse_index_path("abc"), "3/a/abc");
        assert_eq!(sparse_index_path("Serde"), "se/rd/serde");
    }

    #[test]
    fn build_dependency_closure_reaches_normal_transitive_network_packages() {
        let source = "registry+https://github.com/rust-lang/crates.io-index";
        let lock: CargoLock = toml::from_str(&format!(
            r#"version=4
[[package]]
name="parent"
version="1.0.0"
source="{source}"
checksum="a"
dependencies=["helper"]
[[package]]
name="helper"
version="1.0.0"
source="{source}"
checksum="b"
dependencies=["reqwest"]
[[package]]
name="reqwest"
version="1.0.0"
source="{source}"
checksum="c"
"#
        ))
        .unwrap();
        let artifacts = lock.remote_artifacts().unwrap();
        let mut metadata = BTreeMap::new();
        for artifact in artifacts {
            let deps = if artifact.name == "parent" {
                vec![IndexDependency {
                    name: "helper".into(),
                    req: "1".into(),
                    kind: Some("build".into()),
                    package: None,
                }]
            } else {
                Vec::new()
            };
            metadata.insert(
                artifact.clone(),
                IndexVersion {
                    name: artifact.name,
                    vers: artifact.version,
                    deps,
                    cksum: artifact.checksum,
                    yanked: false,
                },
            );
        }
        let findings = stage_one_findings(&lock, &metadata, &BTreeSet::new());
        let reqwest = findings
            .iter()
            .find(|(artifact, _)| artifact.name == "reqwest")
            .unwrap()
            .1;
        assert!(
            reqwest
                .iter()
                .any(|finding| finding.capability == "build-time-network-family")
        );
    }
}
