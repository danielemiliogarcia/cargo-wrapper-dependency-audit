#!/usr/bin/env bash
# Installs Cargo Wrapper from source inside SBX, then exercises Dependency Audit's complete lifecycle.
# The caller supplies private writable source copies; every install, cache, project, and approval stays in SBX.

set -euo pipefail

plugin_source=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
core_source=${CARGO_WRAPPER_SOURCE:-"$HOME/cargowrapper-plugin-host"}
if [[ ! -f "$core_source/Cargo.toml" || ! -f "$core_source/src/plugins.rs" ]]; then
    printf 'error: CARGO_WRAPPER_SOURCE must point to a writable plugin-support source copy\n' >&2
    exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        build-essential ca-certificates curl xz-utils
fi

if [[ ! -x "$HOME/.cargo/bin/cargo" ]]; then
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
        https://sh.rustup.rs --output /tmp/dependency-audit-rustup-init.sh
    sh /tmp/dependency-audit-rustup-init.sh \
        -y --profile minimal --default-toolchain 1.96.0
fi
export PATH="$HOME/.cargo/bin:$PATH"
real_cargo="$HOME/.cargo/bin/cargo"
real_rustc="$HOME/.cargo/bin/rustc"

printf '\n==> Installing Cargo Wrapper from scratch inside SBX\n'
(cd "$core_source" && printf '\n' | "$real_cargo" run --release --locked -- wrapper-install)
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
hash -r
test "$(command -v cargo)" = "$HOME/.local/bin/cargo"
test "$(command -v rustc)" = "$real_rustc"
cargo wrapper
cargo wrapper plugin list | tee "$HOME/wrapper-empty-plugin-list.txt"
grep -F 'No Cargo Wrapper plugins are installed.' "$HOME/wrapper-empty-plugin-list.txt"

printf '\n==> Checking Cargo Wrapper by itself\n'
core_demo="$HOME/cargo-wrapper-alone-demo"
"$real_cargo" new --bin "$core_demo"
(cd "$core_demo" && "$real_cargo" generate-lockfile --offline)
(cd "$core_demo" && cargo build)
if (cd "$core_demo" && cargo update); then
    printf 'error: ordinary cargo update unexpectedly passed the base wrapper\n' >&2
    exit 1
fi
(cd "$core_demo" && cargo forceupdate)

printf '\n==> Building and installing the plugin inactive\n'
(cd "$plugin_source" && "$real_cargo" build --release --locked)
printf '\n==> Running the plugin tests and visible accepted-risk POC inside SBX\n'
(cd "$plugin_source" && "$real_cargo" test --all-targets --locked)
(cd "$plugin_source" && \
    "$real_cargo" test --test security_poc \
        accepting_bad_build_time_code_allows_it_to_execute -- --nocapture)
state_dir="$HOME/dependency-audit-smoke-state"
plugin_root="$state_dir/plugins"
empty_approval_file="$state_dir/empty-approvals.toml"
mkdir -p "$state_dir"
export CARGO_WRAPPER_PLUGIN_DIR="$plugin_root"
export CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE="$empty_approval_file"
export TERM=dumb

cargo wrapper plugin install dependency-audit \
    "$plugin_source/target/release/cargo-wrapper-plugin-dependency-audit"
cargo wrapper plugin list | tee "$state_dir/inactive.txt"
grep -F $'dependency-audit\tinactive' "$state_dir/inactive.txt"

inactive_demo="$HOME/dependency-audit-inactive-demo"
"$real_cargo" new --bin "$inactive_demo"
(cd "$inactive_demo" && "$real_cargo" generate-lockfile --offline)
(cd "$inactive_demo" && cargo build)
test ! -e "$empty_approval_file"

printf '\n==> Enabling and querying Dependency Audit\n'
cargo wrapper plugin enable dependency-audit
cargo wrapper plugin list | tee "$state_dir/active.txt"
grep -F $'dependency-audit\tactive' "$state_dir/active.txt"
(cd "$inactive_demo" && cargo dependency-audit) | tee "$state_dir/status.txt"
grep -F 'Protocol version: 1' "$state_dir/status.txt"
grep -F 'Factory trust bundle: not installed' "$state_dir/status.txt"
installed_plugin="$plugin_root/dependency-audit/plugin"
if "$installed_plugin" >"$state_dir/direct.out" 2>"$state_dir/direct.err"; then
    printf 'error: direct plugin execution unexpectedly succeeded\n' >&2
    exit 1
fi
grep -F 'must be invoked by Cargo Wrapper plugin protocol v1' "$state_dir/direct.err"

printf '\n==> Exercising default-deny Cargo installation and the scoped bypass\n'
install_demo="$HOME/dependency-audit-install-demo"
install_root="$HOME/dependency-audit-install-root"
"$real_cargo" new --bin --name dependency-audit-install-smoke "$install_demo"
(cd "$install_demo" && "$real_cargo" generate-lockfile --offline)
install_rejection_log="$state_dir/install-rejection.txt"
if cargo install --path "$install_demo" --root "$install_root" \
    >"$install_rejection_log" 2>&1; then
    printf 'error: ordinary cargo install unexpectedly bypassed Dependency Audit\n' >&2
    exit 1
fi
grep -F 'Even if you trust the requested package' "$install_rejection_log"
grep -F 'cargo forceinstall --accept-unreviewed-install-risk' "$install_rejection_log"
test ! -e "$install_root/bin/dependency-audit-install-smoke"

forceinstall_rejection_log="$state_dir/forceinstall-rejection.txt"
if cargo forceinstall --path "$install_demo" --root "$install_root" \
    >"$forceinstall_rejection_log" 2>&1; then
    printf 'error: unacknowledged cargo forceinstall unexpectedly succeeded\n' >&2
    exit 1
fi
grep -F 'cargo forceinstall --accept-unreviewed-install-risk' \
    "$forceinstall_rejection_log"
test ! -e "$install_root/bin/dependency-audit-install-smoke"

install_bypass_log="$state_dir/install-bypass.txt"
cargo forceinstall --accept-unreviewed-install-risk \
    --path "$install_demo" --root "$install_root" \
    >"$install_bypass_log" 2>&1
grep -F 'DEPENDENCY AUDIT BYPASS: UNREVIEWED CARGO INSTALL' "$install_bypass_log"
grep -F -- '--accept-unreviewed-install-risk was explicitly provided' \
    "$install_bypass_log"
test -x "$install_root/bin/dependency-audit-install-smoke"

printf '\n==> Exercising interactive evidence and default rejection\n'
review_demo="$HOME/dependency-audit-review-demo"
"$real_cargo" new --bin "$review_demo"
# Pin syn so this exact graph remains identical before and after the dated factory snapshot.
(cd "$review_demo" && "$real_cargo" add syn@=3.0.4)
find "$review_demo/Cargo.lock" -delete
review_log="$state_dir/interactive-review.txt"
if printf 'i\nV\nF\n\nC\nD\nL\nR\n' | \
    (cd "$review_demo" && cargo forceadd serde --features derive) \
    >"$review_log" 2>&1; then
    printf 'error: explicitly rejected dependency operation unexpectedly succeeded\n' >&2
    exit 1
fi
grep -F 'Matched evidence from the checksum-verified archive' "$review_log"
grep -F 'Relevant files from the checksum-verified archive' "$review_log"
grep -F 'Open exact crates.io release: https://crates.io/crates/' "$review_log"
grep -F 'Open exact docs.rs documentation: https://docs.rs/' "$review_log"
grep -F 'BEGIN COPY-READY LLM AUDIT PROMPT' "$review_log"
grep -F 'security review rejected' "$review_log"
if grep -q '^serde' "$review_demo/Cargo.toml"; then
    printf 'error: rejection did not restore Cargo.toml\n' >&2
    exit 1
fi
test ! -e "$empty_approval_file"

printf '\n==> Exercising batch dump and accept-once\n'
once_demo="$HOME/dependency-audit-once-demo"
"$real_cargo" new --bin "$once_demo"
(cd "$once_demo" && cargo forceadd serde --features derive --dump-audit-prompt)
audit_report=$(find "$once_demo" -maxdepth 1 -name 'audit-prompt-*.md' -print -quit)
test -f "$audit_report"
grep -F 'Overall verdict: ACCEPT_ALL' "$audit_report"
grep -F 'Dangerous or uncertain artifacts:' "$audit_report"
grep -F 'DO NOT execute, build, install, test, clone, or import' "$audit_report"
if grep -q '^serde' "$once_demo/Cargo.toml"; then
    printf 'error: audit dump changed Cargo.toml\n' >&2
    exit 1
fi
test ! -e "$empty_approval_file"
(cd "$once_demo" && cargo forceadd serde --features derive --accept-all-once)
grep -q '^serde' "$once_demo/Cargo.toml"
test ! -e "$empty_approval_file"

printf '\n==> Exercising exact persistent approvals and the fast path\n'
remember_demo="$HOME/dependency-audit-remember-demo"
"$real_cargo" new --bin "$remember_demo"
(cd "$remember_demo" && cargo forceadd serde --features derive --accept-and-remember-all)
grep -q '^\[\[approvals\]\]' "$empty_approval_file"
(cd "$remember_demo" && cargo build)

printf '\n==> Comparing an empty store with the optional factory bundle\n'
factory_approval_file="$state_dir/factory-approvals.toml"
export CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE="$factory_approval_file"
if printf '\n' | cargo dependency-audit trust-bundle install; then
    printf 'error: default factory-bundle answer unexpectedly installed it\n' >&2
    exit 1
fi
test ! -e "$factory_approval_file"
printf 'I\n' | cargo dependency-audit trust-bundle install
test "$(grep -c '^\[\[approvals\]\]' "$factory_approval_file")" -eq 2764
cargo dependency-audit | tee "$state_dir/factory-status.txt"
grep -F 'Factory trust bundle: 2026-09-04-fairgate' "$state_dir/factory-status.txt"

# This is the same review_demo operation rejected above, now with the exact bundle installed.
factory_run_log="$state_dir/factory-run.txt"
(cd "$review_demo" && cargo forceadd serde --features derive </dev/null) \
    >"$factory_run_log" 2>&1
grep -q '^serde' "$review_demo/Cargo.toml"
if grep -q 'Choice \[R\]:' "$factory_run_log"; then
    printf 'error: factory-approved exact graph unexpectedly prompted\n' >&2
    exit 1
fi

printf '\n==> Adding and reusing one personal approval outside the factory snapshot\n'
before_count=$(grep -c '^\[\[approvals\]\]' "$factory_approval_file")
printf 'i\nW\n' | \
    (cd "$review_demo" && cargo forceadd proc-macro2@=1.0.104)
after_count=$(grep -c '^\[\[approvals\]\]' "$factory_approval_file")
test "$after_count" -eq "$((before_count + 1))"
(cd "$review_demo" && cargo remove proc-macro2 </dev/null)
personal_reuse_log="$state_dir/personal-reuse.txt"
(cd "$review_demo" && cargo forceadd proc-macro2@=1.0.104 </dev/null) \
    >"$personal_reuse_log" 2>&1
if grep -q 'Choice \[R\]:' "$personal_reuse_log"; then
    printf 'error: exact personal approval was not reused\n' >&2
    exit 1
fi

printf '\n==> Disabling and uninstalling the plugin\n'
cargo wrapper plugin disable dependency-audit
(cd "$once_demo" && cargo build)
cargo wrapper plugin uninstall dependency-audit
test -s "$empty_approval_file"
test -s "$factory_approval_file"
cargo wrapper plugin list | tee "$state_dir/uninstalled.txt"
grep -F 'No Cargo Wrapper plugins are installed.' "$state_dir/uninstalled.txt"

printf '\n============================================================\n'
printf 'COMPLETE DEPENDENCY AUDIT SBX TEST PASSED\n'
printf '============================================================\n'
printf 'Cargo Wrapper worked alone; plugin inactive/active behavior worked.\n'
printf 'Install rejection/bypass, evidence, links, LLM, dump, once, remember, factory, disable, and uninstall checks passed.\n'
printf 'Plugin-owned approvals remained after uninstall, as designed.\n'
