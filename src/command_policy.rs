//! Parses Cargo invocations and assigns the policy for each subcommand.
//! It also maps explicit force commands and inserts `--locked` where required.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandPolicy {
    Passthrough,
    TransparentLocked,
    ApprovedSourceRequired,
    ReviewedDependencyRemoval,
    DependencyMutationRequiresForce,
    InstallRequiresRiskAcceptance,
    SafeMetadataNoDeps,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub command_index: usize,
    pub command: String,
    pub policy: CommandPolicy,
    pub forced_command: Option<String>,
}

const TRANSPARENT_LOCKED: &[&str] = &[
    "build", "test", "run", "check", "bench", "clippy", "fix", "doc", "rustc", "rustdoc",
];
const APPROVED_SOURCE: &[&str] = &["fetch", "vendor", "tree", "package", "publish"];
const FORCE_REQUIRED_MUTATIONS: &[&str] = &["update", "generate-lockfile", "add"];
pub const INSTALL_RISK_ACCEPTANCE_FLAG: &str = "--accept-unreviewed-install-risk";

pub fn classify(args: &[String]) -> Option<Invocation> {
    classify_hosted(args, None)
}

pub fn classify_hosted(args: &[String], original_subcommand: Option<&str>) -> Option<Invocation> {
    let command_index = command_index(args)?;
    let command = args.get(command_index)?.clone();
    let before_separator = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let command_args = &args[command_index + 1..before_separator];

    let host_authorized_update = command == "update" && original_subcommand == Some("forceupdate");
    let (policy, forced_command) = if command == "install" || command == "forceinstall" {
        (CommandPolicy::InstallRequiresRiskAcceptance, None)
    } else if host_authorized_update {
        (
            CommandPolicy::DependencyMutationRequiresForce,
            Some("update".to_owned()),
        )
    } else if let Some(real) = force_mapping(&command) {
        (
            CommandPolicy::DependencyMutationRequiresForce,
            Some(real.to_owned()),
        )
    } else if TRANSPARENT_LOCKED.contains(&command.as_str()) {
        (CommandPolicy::TransparentLocked, None)
    } else if APPROVED_SOURCE.contains(&command.as_str()) {
        (CommandPolicy::ApprovedSourceRequired, None)
    } else if command == "remove" {
        (CommandPolicy::ReviewedDependencyRemoval, None)
    } else if FORCE_REQUIRED_MUTATIONS.contains(&command.as_str()) {
        (CommandPolicy::DependencyMutationRequiresForce, None)
    } else if command == "metadata" && command_args.iter().any(|arg| arg == "--no-deps") {
        (CommandPolicy::SafeMetadataNoDeps, None)
    } else if command == "metadata" {
        (CommandPolicy::ApprovedSourceRequired, None)
    } else {
        (CommandPolicy::Passthrough, None)
    };

    Some(Invocation {
        command_index,
        command,
        policy,
        forced_command,
    })
}

fn command_index(args: &[String]) -> Option<usize> {
    let mut index = usize::from(args.first().is_some_and(|arg| arg.starts_with('+')));
    while let Some(argument) = args.get(index) {
        match argument.as_str() {
            "-v" | "--verbose" | "-q" | "--quiet" | "--frozen" | "--locked" | "--offline" => {
                index += 1;
            }
            "--color" | "--config" | "-Z" => {
                index += 2;
            }
            value
                if value.starts_with("--color=")
                    || value.starts_with("--config=")
                    || (value.starts_with("-Z") && value.len() > 2) =>
            {
                index += 1;
            }
            _ => return Some(index),
        }
    }
    None
}

pub fn manifest_path(args: &[String], cwd: &std::path::Path) -> Option<std::path::PathBuf> {
    let end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let mut index = 0;
    while index < end {
        if args[index] == "--manifest-path" {
            let path = args.get(index + 1)?;
            return Some(resolve_path(cwd, path));
        }
        if let Some(path) = args[index].strip_prefix("--manifest-path=") {
            return Some(resolve_path(cwd, path));
        }
        index += 1;
    }
    None
}

fn resolve_path(cwd: &std::path::Path, path: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

pub fn force_mapping(command: &str) -> Option<&'static str> {
    match command {
        "forceupdate" => Some("update"),
        "forcegenerate-lockfile" => Some("generate-lockfile"),
        "forceadd" => Some("add"),
        "forceremove" => Some("remove"),
        _ => None,
    }
}

pub fn add_locked(args: &mut Vec<String>, command_index: usize) {
    let end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    if !args[..end].iter().any(|arg| arg == "--locked") {
        args.insert(command_index + 1, "--locked".to_owned());
    }
}

pub fn blocked_message(command: &str, args: &[String], command_index: usize) -> Option<String> {
    if command == "install" || command == "forceinstall" {
        let mut suggestion = args.to_vec();
        suggestion[command_index] = "forceinstall".to_owned();
        suggestion.insert(command_index + 1, INSTALL_RISK_ACCEPTANCE_FLAG.to_owned());
        return Some(format!(
            "dependency-audit: `cargo {command}` is blocked because its dependency graph cannot be reviewed before download.\n\nCargo installation downloads and compiles a separate package and its dependency graph. Even if you trust the requested package, its current transitive dependencies, build scripts, or procedural macros could be compromised and execute with your user privileges. Dependency Audit cannot currently resolve and review that complete graph without first allowing Cargo to download unreviewed source. Real Cargo was not invoked.\n\nSafer option: perform the installation in an isolated, disposable sandbox.\n\nTo proceed once without Dependency Audit inspection, explicitly accept the unreviewed installation risk:\n\n    cargo {}\n\n`cargo forceadd` is not an alternative: it adds a dependency to the current project instead of installing an executable.",
            suggestion.join(" ")
        ));
    }
    let force = match command {
        "update" => "forceupdate",
        "generate-lockfile" => "forcegenerate-lockfile",
        "add" => "forceadd",
        _ => return None,
    };
    let reason = match command {
        "generate-lockfile" => "creates or rebuilds the trusted dependency graph",
        _ => "can change the trusted dependency graph",
    };
    let mut suggestion = args.to_vec();
    suggestion[command_index] = force.to_owned();
    Some(format!(
        "dependency-audit: `cargo {command}` {reason}.\n\nUse:\n\n    cargo {}\n\nto resolve and security-review the candidate dependency set first.",
        suggestion.join(" ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn classifies_all_protected_commands() {
        for command in TRANSPARENT_LOCKED {
            assert_eq!(
                classify(&strings(&[command])).unwrap().policy,
                CommandPolicy::TransparentLocked
            );
        }
        for command in APPROVED_SOURCE {
            assert_eq!(
                classify(&strings(&[command])).unwrap().policy,
                CommandPolicy::ApprovedSourceRequired
            );
        }
        assert_eq!(
            classify(&strings(&["metadata"])).unwrap().policy,
            CommandPolicy::ApprovedSourceRequired
        );
        assert_eq!(
            classify(&strings(&["metadata", "--no-deps"]))
                .unwrap()
                .policy,
            CommandPolicy::SafeMetadataNoDeps
        );
    }

    #[test]
    fn maps_force_commands_and_preserves_toolchain_position() {
        for (forced, real) in [
            ("forceupdate", "update"),
            ("forcegenerate-lockfile", "generate-lockfile"),
            ("forceadd", "add"),
            ("forceremove", "remove"),
        ] {
            let invocation = classify(&strings(&["+nightly", forced, "x"])).unwrap();
            assert_eq!(invocation.command_index, 1);
            assert_eq!(invocation.forced_command.as_deref(), Some(real));
        }
    }

    #[test]
    fn install_rejection_provides_the_complete_scoped_bypass() {
        for command in ["install", "forceinstall"] {
            let args = strings(&[command, "demo"]);
            let invocation = classify(&args).unwrap();
            assert_eq!(
                invocation.policy,
                CommandPolicy::InstallRequiresRiskAcceptance
            );
            assert_eq!(invocation.forced_command, None);

            let message = blocked_message(command, &args, 0).unwrap();
            assert!(message.contains("is blocked"));
            assert!(message.contains("Real Cargo was not invoked"));
            assert!(message.contains("cargo forceinstall --accept-unreviewed-install-risk demo"));
            assert!(message.contains("`cargo forceadd` is not an alternative"));
        }
    }

    #[test]
    fn recognizes_only_the_host_vouched_forceupdate_rewrite() {
        let hosted = classify_hosted(&strings(&["update"]), Some("forceupdate")).unwrap();
        assert_eq!(hosted.forced_command.as_deref(), Some("update"));
        assert_eq!(
            hosted.policy,
            CommandPolicy::DependencyMutationRequiresForce
        );

        let ordinary = classify_hosted(&strings(&["update"]), Some("update")).unwrap();
        assert_eq!(ordinary.forced_command, None);
    }

    #[test]
    fn ordinary_remove_uses_a_reviewed_transaction_without_force() {
        let invocation = classify(&strings(&["remove", "serde"])).unwrap();
        assert_eq!(invocation.policy, CommandPolicy::ReviewedDependencyRemoval);
        assert_eq!(invocation.forced_command, None);
        assert!(blocked_message("remove", &strings(&["remove", "serde"]), 0).is_none());
    }

    #[test]
    fn global_options_cannot_hide_a_protected_command() {
        let invocation = classify(&strings(&[
            "+stable", "--locked", "--color", "always", "build",
        ]))
        .unwrap();
        assert_eq!(invocation.command, "build");
        assert_eq!(invocation.command_index, 4);
        assert_eq!(invocation.policy, CommandPolicy::TransparentLocked);
    }

    #[test]
    fn locked_is_inserted_before_command_arguments_but_not_program_arguments() {
        let mut args = strings(&["run", "--", "--locked"]);
        add_locked(&mut args, 0);
        assert_eq!(args, strings(&["run", "--locked", "--", "--locked"]));
    }

    #[test]
    fn blocked_suggestion_preserves_toolchain_and_arguments() {
        let args = strings(&["+nightly", "add", "serde", "--features", "derive"]);
        let message = blocked_message("add", &args, 1).unwrap();
        assert!(message.contains("cargo +nightly forceadd serde --features derive"));
    }
}
