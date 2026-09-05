//! Entry point for the Cargo Wrapper dependency-audit middleware plugin.
//! It validates protocol v1, reviews dependency changes, and calls the next stage only when allowed.

use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use cargo_wrapper_dependency_audit::approvals::ApprovalStore;
use cargo_wrapper_dependency_audit::candidate::{
    WorkspaceSnapshot, locks_match, resolve_candidate,
};
use cargo_wrapper_dependency_audit::command_policy::{
    CommandPolicy, INSTALL_RISK_ACCEPTANCE_FLAG, add_locked, blocked_message, classify_hosted,
    manifest_path,
};
use cargo_wrapper_dependency_audit::factory_approvals::FactoryBundle;
use cargo_wrapper_dependency_audit::lockfile::CargoLock;
use cargo_wrapper_dependency_audit::prompt::{
    BatchDecisionProvider, Decision, DecisionProvider, InteractivePrompt,
};
use cargo_wrapper_dependency_audit::protocol::{self, ProtocolContext};
use cargo_wrapper_dependency_audit::registry::HttpRegistryClient;
use cargo_wrapper_dependency_audit::scanner::SCANNER_VERSION;
use cargo_wrapper_dependency_audit::security::SecurityGate;
use cargo_wrapper_dependency_audit::workspace::{Workspace, project_root};
use cargo_wrapper_dependency_audit::{Result as AuditResult, error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReviewMode {
    Interactive,
    DumpAuditPrompt,
    AcceptAllOnce,
    AcceptAndRememberAll,
}

impl ReviewMode {
    fn automatic_decision(self) -> Option<Decision> {
        match self {
            Self::Interactive => None,
            Self::DumpAuditPrompt | Self::AcceptAllOnce => Some(Decision::AcceptOnce),
            Self::AcceptAndRememberAll => Some(Decision::AcceptAndRemember),
        }
    }
}

fn extract_review_mode(args: &mut Vec<String>) -> AuditResult<ReviewMode> {
    let option_end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let mut selected = None;
    let mut retained = Vec::with_capacity(args.len());

    for (index, argument) in args.drain(..).enumerate() {
        let mode = if index < option_end {
            match argument.as_str() {
                "--dump-audit-prompt" => Some(ReviewMode::DumpAuditPrompt),
                "--accept-all-once" => Some(ReviewMode::AcceptAllOnce),
                "--accept-and-remember-all" => Some(ReviewMode::AcceptAndRememberAll),
                _ => None,
            }
        } else {
            None
        };
        if let Some(mode) = mode {
            if selected.replace(mode).is_some() {
                return Err(error(
                    "dependency-audit: specify exactly one batch review option: --dump-audit-prompt, --accept-all-once, or --accept-and-remember-all",
                ));
            }
        } else {
            retained.push(argument);
        }
    }
    *args = retained;
    Ok(selected.unwrap_or(ReviewMode::Interactive))
}

fn extract_install_risk_acceptance(args: &mut Vec<String>) -> AuditResult<bool> {
    let option_end = args
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(args.len());
    let mut accepted = false;
    let mut retained = Vec::with_capacity(args.len());

    for (index, argument) in args.drain(..).enumerate() {
        if index < option_end && argument == INSTALL_RISK_ACCEPTANCE_FLAG {
            if accepted {
                return Err(error(format!(
                    "dependency-audit: specify {INSTALL_RISK_ACCEPTANCE_FLAG} only once"
                )));
            }
            accepted = true;
        } else {
            retained.push(argument);
        }
    }
    *args = retained;
    Ok(accepted)
}

fn announce_unreviewed_install_bypass() {
    eprintln!(
        "============================================================\n\
         DEPENDENCY AUDIT BYPASS: UNREVIEWED CARGO INSTALL\n\
         ============================================================\n\n\
         The requested package and its transitive dependency graph were not\n\
         reviewed by Dependency Audit. Build scripts and procedural macros may\n\
         execute with your user privileges. Proceeding only because\n\
         {INSTALL_RISK_ACCEPTANCE_FLAG} was explicitly provided.\n"
    );
}

fn format_utc_timestamp(seconds: u64, milliseconds: u32) -> String {
    let days = (seconds / 86_400) as i64;
    let seconds_in_day = seconds % 86_400;
    let hour = seconds_in_day / 3_600;
    let minute = (seconds_in_day % 3_600) / 60;
    let second = seconds_in_day % 60;
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
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z")
}

fn utc_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_utc_timestamp(now.as_secs(), now.subsec_millis())
}

fn write_audit_prompt_report(cwd: &Path, report: &str) -> AuditResult<PathBuf> {
    let compact_timestamp: String = utc_timestamp()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    for suffix in 0..1_000 {
        let suffix = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let path = cwd.join(format!("audit-prompt-{compact_timestamp}{suffix}.md"));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                if let Err(write_error) = file
                    .write_all(report.as_bytes())
                    .and_then(|()| file.sync_all())
                {
                    let _ = std::fs::remove_file(&path);
                    return Err(write_error.into());
                }
                return Ok(path);
            }
            Err(open_error) if open_error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(open_error) => return Err(open_error.into()),
        }
    }
    Err(error(
        "dependency-audit: could not allocate a unique timestamped audit-prompt filename",
    ))
}

fn finish_audit_dump(cwd: &Path, reviews: &BatchDecisionProvider) -> AuditResult<i32> {
    let path = write_audit_prompt_report(cwd, &reviews.audit_prompt_markdown())?;
    let absolute_path = path.canonicalize().unwrap_or(path);
    println!(
        "Dependency Audit created an audit prompt for {} unapproved artifact{} at:\n{}",
        reviews.review_count(),
        if reviews.review_count() == 1 { "" } else { "s" },
        absolute_path.display()
    );
    println!(
        "\nTell your LLM or coding agent:\n\nFollow every instruction in the audit file at \"{}\". Review every artifact, do not execute any crate code, and return the required overall verdict.",
        absolute_path.display()
    );
    println!("\nThe requested Cargo operation was not run.");
    Ok(0)
}

fn announce_batch_acceptance(mode: ReviewMode, reviews: &BatchDecisionProvider) {
    match mode {
        ReviewMode::AcceptAllOnce => {
            eprintln!(
                "dependency-audit: explicitly accepting all findings for {} currently resolved unapproved artifact{} once:",
                reviews.review_count(),
                if reviews.review_count() == 1 { "" } else { "s" }
            );
            eprint!("{}", reviews.artifact_summary());
            eprintln!("checksum and inspection failures remain non-overridable");
        }
        ReviewMode::AcceptAndRememberAll => {
            eprintln!(
                "dependency-audit: explicitly accepting and remembering all findings for {} currently resolved exact artifact{}:",
                reviews.review_count(),
                if reviews.review_count() == 1 { "" } else { "s" }
            );
            eprint!("{}", reviews.artifact_summary());
            eprintln!("checksum and inspection failures remain non-overridable");
        }
        ReviewMode::Interactive | ReviewMode::DumpAuditPrompt => {}
    }
}

fn print_factory_bundle_summary(bundle: &FactoryBundle) {
    println!("Dependency Audit trust bundle {}", bundle.bundle_version);
    println!("Reviewed: {}", bundle.reviewed_at);
    println!("{}", bundle.description);
    println!("Exact artifact approvals: {}", bundle.approval_count());
}

fn print_factory_bundle(bundle: &FactoryBundle) {
    print_factory_bundle_summary(bundle);
    println!();
    for entry in bundle.approvals() {
        println!("{} {}", entry.name, entry.version);
        println!("  source:   {}", entry.source);
        println!("  checksum: {}", entry.checksum);
        println!(
            "  findings: {}",
            if entry.approved_findings.is_empty() {
                "none".to_owned()
            } else {
                entry
                    .approved_findings
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
        println!();
    }
}

fn manage_factory_bundle(arguments: &[String]) -> AuditResult<i32> {
    let bundle = FactoryBundle::embedded()?;
    match arguments {
        [action] if action == "show" => {
            print_factory_bundle(&bundle);
            Ok(0)
        }
        [action] if action == "install" => {
            print_factory_bundle_summary(&bundle);
            eprint!(
                "\nRun `cargo dependency-audit trust-bundle show` to inspect every entry.\n\
                 Installing this bundle trusts all {} exact artifacts and their listed findings\n\
                 without downloading and rescanning their source. Future versions or different\n\
                 checksums remain untrusted and will prompt normally.\n\n\
                 [I] Install bundle\n[R] Reject\n\nChoice [R]: ",
                bundle.approval_count()
            );
            io::stderr().flush()?;
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim().to_ascii_lowercase().as_str(), "i") {
                eprintln!("Factory trust bundle installation rejected; no approvals were changed.");
                return Ok(1);
            }
            let path = ApprovalStore::default_path()?;
            let mut store = ApprovalStore::load(path.clone())?;
            let changed = bundle.install(&mut store)?;
            store.save()?;
            println!(
                "Installed {changed} new or updated exact artifact approval{} into {}.",
                if changed == 1 { "" } else { "s" },
                path.display()
            );
            println!("Future crate versions and checksum changes will still require review.");
            Ok(0)
        }
        _ => Err(error(
            "usage: cargo dependency-audit trust-bundle <show|install>",
        )),
    }
}

fn manage_plugin(arguments: &[String]) -> AuditResult<i32> {
    if arguments.is_empty() {
        let path = ApprovalStore::default_path()?;
        let store = ApprovalStore::load(path.clone())?;
        println!("Dependency Audit plugin is active.");
        println!("Plugin version: {}", env!("CARGO_PKG_VERSION"));
        println!("Protocol version: {}", protocol::PROTOCOL_VERSION);
        println!("Scanner version: {SCANNER_VERSION}");
        println!("Approval file: {}", path.display());
        if store.installed_factory_bundles().is_empty() {
            println!("Factory trust bundle: not installed");
        } else {
            println!(
                "Factory trust bundle: {}",
                store
                    .installed_factory_bundles()
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return Ok(0);
    }
    if arguments.first().is_some_and(|arg| arg == "trust-bundle") {
        return manage_factory_bundle(&arguments[1..]);
    }
    Err(error(
        "usage: cargo dependency-audit [trust-bundle <show|install>]",
    ))
}

fn run_downstream(protocol: &ProtocolContext, args: &[String], cwd: &Path) -> AuditResult<i32> {
    let status = protocol.downstream.run(args, cwd)?;
    Ok(status.code().unwrap_or(1))
}

fn plugin_main(protocol: ProtocolContext) -> AuditResult<i32> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let review_mode = extract_review_mode(&mut args)?;
    let install_risk_accepted = extract_install_risk_acceptance(&mut args)?;
    let invocation = classify_hosted(&args, protocol.original_subcommand.as_deref());

    if install_risk_accepted
        && !matches!(
            invocation.as_ref(),
            Some(invocation) if invocation.command == "forceinstall"
        )
    {
        return Err(error(format!(
            "dependency-audit: {INSTALL_RISK_ACCEPTANCE_FLAG} is valid only with `cargo forceinstall`"
        )));
    }

    if install_risk_accepted && review_mode != ReviewMode::Interactive {
        return Err(error(
            "dependency-audit: the unreviewed install-risk acceptance flag cannot be combined with batch audit options",
        ));
    }

    if let Some(invocation) = &invocation
        && invocation.command == "dependency-audit"
    {
        if review_mode != ReviewMode::Interactive {
            return Err(error(
                "dependency-audit: batch review options are not valid for plugin administration",
            ));
        }
        return manage_plugin(&args[invocation.command_index + 1..]);
    }

    let Some(invocation) = invocation else {
        if review_mode != ReviewMode::Interactive {
            return Err(error(
                "dependency-audit: batch review options require a Cargo operation guarded by dependency review",
            ));
        }
        return run_downstream(&protocol, &args, &env::current_dir()?);
    };

    if invocation.policy == CommandPolicy::InstallRequiresRiskAcceptance {
        if install_risk_accepted {
            args[invocation.command_index] = "install".to_owned();
            add_locked(&mut args, invocation.command_index);
            announce_unreviewed_install_bypass();
            return run_downstream(&protocol, &args, &env::current_dir()?);
        }
        return Err(error(
            blocked_message(&invocation.command, &args, invocation.command_index)
                .unwrap_or_else(|| "dependency-audit: Cargo installation is blocked".to_owned()),
        ));
    }

    if invocation.forced_command.is_none()
        && invocation.policy == CommandPolicy::DependencyMutationRequiresForce
    {
        return Err(error(
            blocked_message(&invocation.command, &args, invocation.command_index)
                .unwrap_or_else(|| "dependency-audit: dependency mutation is blocked".to_owned()),
        ));
    }
    let guarded_operation = invocation.forced_command.is_some()
        || matches!(
            invocation.policy,
            CommandPolicy::ReviewedDependencyRemoval
                | CommandPolicy::TransparentLocked
                | CommandPolicy::ApprovedSourceRequired
        );
    if review_mode != ReviewMode::Interactive && !guarded_operation {
        return Err(error(
            "dependency-audit: batch review options are only valid for Cargo operations guarded by dependency review",
        ));
    }

    let cwd = env::current_dir()?.canonicalize()?;
    let workspace_start = manifest_path(&args, &cwd)
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| cwd.clone());

    if invocation.forced_command.is_some()
        || invocation.policy == CommandPolicy::ReviewedDependencyRemoval
    {
        let root = project_root(&workspace_start)?;
        let candidate = resolve_candidate(&protocol.direct_cargo, &root, &cwd, &args, &invocation)?;
        let candidate_workspace = Workspace::discover(&candidate.workspace_root)?;
        let candidate_lock = candidate.lock()?;
        let mut store = ApprovalStore::load(ApprovalStore::default_path()?)?;
        let registry = HttpRegistryClient::default();
        let mut interactive = InteractivePrompt;
        let mut batch = BatchDecisionProvider::new(
            review_mode
                .automatic_decision()
                .unwrap_or(Decision::AcceptOnce),
        );
        let outcome = {
            let decisions: &mut dyn DecisionProvider = if review_mode == ReviewMode::Interactive {
                &mut interactive
            } else {
                &mut batch
            };
            let mut gate = SecurityGate {
                store: &mut store,
                registry: &registry,
                decisions,
            };
            gate.review_workspace(&candidate_workspace)?
        };
        if review_mode == ReviewMode::DumpAuditPrompt {
            return finish_audit_dump(&cwd, &batch);
        }
        announce_batch_acceptance(review_mode, &batch);

        let snapshot = WorkspaceSnapshot::capture(&root)?;
        if let Some(forced_command) = &invocation.forced_command {
            args[invocation.command_index] = forced_command.clone();
        }
        let status = protocol.downstream.run(&args, &cwd)?;
        if !status.success() {
            snapshot.restore()?;
            return Err(error(format!(
                "dependency-audit: final Cargo operation failed with {status}; original manifests and lockfile were restored"
            )));
        }
        let real_workspace = Workspace::discover(&workspace_start)?;
        let real_lock = CargoLock::parse(&real_workspace.lockfile)?;
        if !locks_match(&candidate_lock, &real_lock)? {
            snapshot.restore()?;
            return Err(error(
                "dependency-audit: final Cargo.lock differs from the reviewed candidate; original workspace files were restored and re-review is required",
            ));
        }
        if outcome.fully_remembered {
            let fingerprint = real_workspace.fingerprint()?;
            let (lock_hash, manifests_hash) = real_workspace.component_hashes()?;
            store.remember_workspace(
                &real_workspace.root,
                &fingerprint,
                &lock_hash,
                &manifests_hash,
            );
        }
        if review_mode != ReviewMode::AcceptAllOnce {
            store.save()?;
        }
        return Ok(status.code().unwrap_or(1));
    }

    if matches!(
        invocation.policy,
        CommandPolicy::TransparentLocked | CommandPolicy::ApprovedSourceRequired
    ) {
        let workspace = Workspace::discover(&workspace_start)?;
        let mut store = ApprovalStore::load(ApprovalStore::default_path()?)?;
        let registry = HttpRegistryClient::default();
        let mut interactive = InteractivePrompt;
        let mut batch = BatchDecisionProvider::new(
            review_mode
                .automatic_decision()
                .unwrap_or(Decision::AcceptOnce),
        );
        let fast = {
            let decisions: &mut dyn DecisionProvider = if review_mode == ReviewMode::Interactive {
                &mut interactive
            } else {
                &mut batch
            };
            let gate = SecurityGate {
                store: &mut store,
                registry: &registry,
                decisions,
            };
            gate.fast_path(&workspace)?
        };
        if fast.is_none() {
            let outcome = {
                let decisions: &mut dyn DecisionProvider = if review_mode == ReviewMode::Interactive
                {
                    &mut interactive
                } else {
                    &mut batch
                };
                let mut gate = SecurityGate {
                    store: &mut store,
                    registry: &registry,
                    decisions,
                };
                gate.review_workspace(&workspace)?
            };
            if review_mode == ReviewMode::DumpAuditPrompt {
                return finish_audit_dump(&cwd, &batch);
            }
            announce_batch_acceptance(review_mode, &batch);
            if outcome.fully_remembered {
                let (lock_hash, manifests_hash) = workspace.component_hashes()?;
                store.remember_workspace(
                    &workspace.root,
                    &outcome.fingerprint,
                    &lock_hash,
                    &manifests_hash,
                );
            }
            if review_mode != ReviewMode::AcceptAllOnce {
                store.save()?;
            }
        } else if review_mode == ReviewMode::DumpAuditPrompt {
            return finish_audit_dump(&cwd, &batch);
        } else {
            announce_batch_acceptance(review_mode, &batch);
        }
        add_locked(&mut args, invocation.command_index);
        if env::var_os("CARGO_WRAPPER_DEPENDENCY_AUDIT_VERBOSE").is_some() {
            eprintln!("dependency-audit: approved trust state; enforcing --locked");
        }
    }

    run_downstream(&protocol, &args, &cwd)
}

fn direct_help() {
    println!(
        "cargo-wrapper-plugin-dependency-audit {}\n\nThis binary is a Cargo Wrapper protocol-v1 plugin.\nInstall it with:\n  cargo wrapper plugin install dependency-audit <local-binary>\n  cargo wrapper plugin enable dependency-audit\n\nThen run:\n  cargo dependency-audit",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let direct_arguments: Vec<String> = env::args().skip(1).collect();
    if !protocol::is_host_invocation() {
        if direct_arguments.as_slice() == ["--version"] {
            println!(
                "cargo-wrapper-plugin-dependency-audit {}",
                env!("CARGO_PKG_VERSION")
            );
            return;
        }
        if matches!(direct_arguments.as_slice(), [argument] if argument == "--help" || argument == "-h")
        {
            direct_help();
            return;
        }
        eprintln!(
            "dependency-audit: this binary must be invoked by Cargo Wrapper plugin protocol v1.\nInstall it with `cargo wrapper plugin install dependency-audit <local-binary>`, then enable it."
        );
        exit(2);
    }

    match ProtocolContext::from_environment().and_then(plugin_main) {
        Ok(code) => exit(code),
        Err(audit_error) => {
            eprintln!("{audit_error}");
            exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn batch_review_options_are_removed_before_cargo_parsing() {
        for (option, expected) in [
            ("--dump-audit-prompt", ReviewMode::DumpAuditPrompt),
            ("--accept-all-once", ReviewMode::AcceptAllOnce),
            (
                "--accept-and-remember-all",
                ReviewMode::AcceptAndRememberAll,
            ),
        ] {
            let mut args = strings(&["forceadd", "serde", option]);
            assert_eq!(extract_review_mode(&mut args).unwrap(), expected);
            assert_eq!(args, strings(&["forceadd", "serde"]));
        }
    }

    #[test]
    fn batch_options_after_separator_are_preserved_for_the_child() {
        let mut args = strings(&["run", "--", "--accept-all-once"]);
        assert_eq!(
            extract_review_mode(&mut args).unwrap(),
            ReviewMode::Interactive
        );
        assert_eq!(args, strings(&["run", "--", "--accept-all-once"]));
    }

    #[test]
    fn multiple_batch_options_fail_closed() {
        let mut args = strings(&["build", "--accept-all-once", "--dump-audit-prompt"]);
        assert!(extract_review_mode(&mut args).is_err());
    }

    #[test]
    fn install_risk_acceptance_is_private_exact_and_before_separator_only() {
        let mut args = strings(&[
            "forceinstall",
            INSTALL_RISK_ACCEPTANCE_FLAG,
            "demo",
            "--",
            INSTALL_RISK_ACCEPTANCE_FLAG,
        ]);
        assert!(extract_install_risk_acceptance(&mut args).unwrap());
        assert_eq!(
            args,
            strings(&["forceinstall", "demo", "--", INSTALL_RISK_ACCEPTANCE_FLAG])
        );

        let mut duplicate = strings(&[
            "forceinstall",
            INSTALL_RISK_ACCEPTANCE_FLAG,
            INSTALL_RISK_ACCEPTANCE_FLAG,
            "demo",
        ]);
        assert!(extract_install_risk_acceptance(&mut duplicate).is_err());
    }

    #[test]
    fn formats_utc_timestamps_without_external_dependencies() {
        assert_eq!(format_utc_timestamp(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_utc_timestamp(1_735_689_599, 123),
            "2024-12-31T23:59:59.123Z"
        );
    }
}
