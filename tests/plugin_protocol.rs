//! Verifies protocol refusal, downstream argument fidelity, environment preservation, and status.
//! The downstream fixture is compiled at test time and never invokes Cargo or crate source.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "dependency-audit-protocol-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cargo-wrapper-plugin-dependency-audit")
}

fn compile_fixture(directory: &Path) -> PathBuf {
    let source = directory.join("downstream.rs");
    let executable = directory.join(format!("downstream{}", env::consts::EXE_SUFFIX));
    fs::write(
        &source,
        r#"
use std::{env, fs, process::exit};

fn main() {
    let trace = env::var_os("PROTOCOL_TRACE").unwrap();
    let args: Vec<String> = env::args().skip(1).collect();
    let chain = env::var("CARGO_WRAPPER_PLUGIN_CHAIN").unwrap_or_default();
    let index = env::var("CARGO_WRAPPER_PLUGIN_INDEX").unwrap_or_default();
    fs::write(trace, format!("args={args:?}\nchain={chain}\nindex={index}\n")).unwrap();
    let code = env::var("DOWNSTREAM_EXIT").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    exit(code);
}
"#,
    )
    .unwrap();
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

fn hosted_command(executable: &Path) -> Command {
    let mut command = Command::new(binary());
    command
        .env("CARGO_WRAPPER_PLUGIN_PROTOCOL", "1")
        .env("CARGO_WRAPPER_PLUGIN_NAME", "dependency-audit")
        .env("CARGO_WRAPPER_REAL_CARGO", executable)
        .env("CARGO_WRAPPER_NEXT", executable);
    command
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn direct_execution_is_refused_but_version_and_help_are_read_only() {
    let refused = Command::new(binary()).output().unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(stderr(&refused).contains("must be invoked by Cargo Wrapper"));

    for argument in ["--version", "--help"] {
        let output = Command::new(binary()).arg(argument).output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("dependency-audit"));
    }
}

#[test]
fn malformed_or_incompatible_protocol_fails_closed() {
    let directory = TestDirectory::new();
    let fixture = compile_fixture(&directory.0);

    let wrong_version = Command::new(binary())
        .env("CARGO_WRAPPER_PLUGIN_PROTOCOL", "2")
        .output()
        .unwrap();
    assert!(!wrong_version.status.success());
    assert!(stderr(&wrong_version).contains("unsupported plugin protocol"));

    let wrong_name = Command::new(binary())
        .env("CARGO_WRAPPER_PLUGIN_PROTOCOL", "1")
        .env("CARGO_WRAPPER_PLUGIN_NAME", "something-else")
        .output()
        .unwrap();
    assert!(!wrong_name.status.success());
    assert!(stderr(&wrong_name).contains("expected \"dependency-audit\""));

    let relative_cargo = Command::new(binary())
        .arg("clean")
        .env("CARGO_WRAPPER_PLUGIN_PROTOCOL", "1")
        .env("CARGO_WRAPPER_PLUGIN_NAME", "dependency-audit")
        .env("CARGO_WRAPPER_REAL_CARGO", "relative-cargo")
        .env("CARGO_WRAPPER_NEXT", &fixture)
        .output()
        .unwrap();
    assert!(!relative_cargo.status.success());
    assert!(stderr(&relative_cargo).contains("must be an absolute path"));

    let missing_next = Command::new(binary())
        .arg("clean")
        .env("CARGO_WRAPPER_PLUGIN_PROTOCOL", "1")
        .env("CARGO_WRAPPER_PLUGIN_NAME", "dependency-audit")
        .env("CARGO_WRAPPER_REAL_CARGO", &fixture)
        .output()
        .unwrap();
    assert!(!missing_next.status.success());
    assert!(stderr(&missing_next).contains("CARGO_WRAPPER_NEXT"));
}

#[test]
fn passthrough_preserves_arguments_reserved_environment_and_exit_status() {
    let directory = TestDirectory::new();
    let fixture = compile_fixture(&directory.0);
    let trace = directory.0.join("trace");
    let output = hosted_command(&fixture)
        .args(["clean", "space value", "雪", "--", "--child-option"])
        .env("PROTOCOL_TRACE", &trace)
        .env("DOWNSTREAM_EXIT", "37")
        .env(
            "CARGO_WRAPPER_PLUGIN_CHAIN",
            "dependency-audit,later-plugin",
        )
        .env("CARGO_WRAPPER_PLUGIN_INDEX", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37));
    let trace = fs::read_to_string(trace).unwrap();
    assert!(
        trace.contains("args=[\"clean\", \"space value\", \"雪\", \"--\", \"--child-option\"]")
    );
    assert!(trace.contains("chain=dependency-audit,later-plugin"));
    assert!(trace.contains("index=1"));
}

#[test]
fn plugin_owned_status_never_calls_downstream() {
    let directory = TestDirectory::new();
    let fixture = compile_fixture(&directory.0);
    let trace = directory.0.join("trace");
    let approval_file = directory.0.join("approvals.toml");
    let output = hosted_command(&fixture)
        .arg("dependency-audit")
        .env("PROTOCOL_TRACE", &trace)
        .env(
            "CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE",
            approval_file,
        )
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!trace.exists());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Dependency Audit plugin is active"));
    assert!(stdout.contains("Protocol version: 1"));
}

#[test]
fn install_and_unacknowledged_forceinstall_fail_closed_with_complete_bypass() {
    let directory = TestDirectory::new();
    let fixture = compile_fixture(&directory.0);

    for command in ["install", "forceinstall"] {
        let trace = directory.0.join(format!("{command}-trace"));
        let output = hosted_command(&fixture)
            .args([command, "example-package"])
            .env("PROTOCOL_TRACE", &trace)
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(!trace.exists(), "{command} invoked downstream Cargo");
        let message = stderr(&output);
        assert!(message.contains("is blocked"));
        assert!(message.contains("Real Cargo was not invoked"));
        assert!(
            message.contains("cargo forceinstall --accept-unreviewed-install-risk example-package")
        );
        assert!(message.contains("`cargo forceadd` is not an alternative"));
    }
}

#[test]
fn acknowledged_forceinstall_warns_strips_private_flag_and_calls_downstream_once() {
    let directory = TestDirectory::new();
    let fixture = compile_fixture(&directory.0);
    let trace = directory.0.join("trace");
    let output = hosted_command(&fixture)
        .args([
            "forceinstall",
            "--accept-unreviewed-install-risk",
            "example-package",
            "--version",
            "1.2.3",
        ])
        .env("PROTOCOL_TRACE", &trace)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    let message = stderr(&output);
    assert!(message.contains("DEPENDENCY AUDIT BYPASS: UNREVIEWED CARGO INSTALL"));
    assert!(message.contains("transitive dependency graph were not"));
    assert!(message.contains("reviewed by Dependency Audit"));

    let trace = fs::read_to_string(trace).unwrap();
    assert!(trace.contains(
        "args=[\"install\", \"--locked\", \"example-package\", \"--version\", \"1.2.3\"]"
    ));
    assert!(!trace.contains("accept-unreviewed-install-risk"));
}
