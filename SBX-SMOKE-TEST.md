<!-- Complete Docker Sandbox procedure for installing and testing Cargo Wrapper plus Dependency Audit. -->
# Fresh Docker SBX installation and dependency-audit test

This guide installs Rust, Cargo Wrapper, and Dependency Audit entirely inside a disposable Docker Sandbox (`sbx`). It verifies Cargo Wrapper alone before installing the plugin, then exercises the plugin inactive, enabled, disabled, and uninstalled.

The sandbox has its own home directory, Cargo cache, Rust toolchain, installed binaries, projects, and approval files. The `--clone` workspace is private even though it uses the same visible path as the host repository. Removing the sandbox removes all those files; it does not install or uninstall anything on the host.

The commands assume these host repositories:

```text
/home/emi/tmp/cargowrapper                   on plugin-support
/home/emi/tmp/cargo-wrapper-dependency-audit standalone plugin
```

## 1. Check the host inputs

On the host:

```sh
command -v sbx
git -C /home/emi/tmp/cargowrapper branch --show-current
git -C /home/emi/tmp/cargo-wrapper-dependency-audit status --short
```

The core branch should be `plugin-support`. An untracked standalone tree is expected before its first commit.

## 2. Create a fresh clone-mode Docker Sandbox

The primary SBX workspace must be writable, so do not append `:ro`:

```sh
cd /home/emi/tmp/cargo-wrapper-dependency-audit

sbx run \
  --name dependency-audit-complete-smoke \
  --memory 8g \
  --clone \
  shell
```

When the initial sandbox shell appears, run `exit`. The sandbox remains available.

`--clone` carries committed Git content, but it does not reliably include unstaged and untracked work. Copy the exact current trees into private writable sandbox locations. Host `target` directories and Git metadata are deliberately excluded:

```sh
cd /home/emi/tmp/cargo-wrapper-dependency-audit
tar --exclude=.git --exclude=target -cf - . | \
  sbx exec -i -w "$PWD" dependency-audit-complete-smoke tar -xf -

sbx exec dependency-audit-complete-smoke \
  mkdir -p /home/agent/cargowrapper-plugin-host

cd /home/emi/tmp/cargowrapper
tar --exclude=.git --exclude=target -cf - . | \
  sbx exec -i dependency-audit-complete-smoke \
    tar -xf - -C /home/agent/cargowrapper-plugin-host
```

Everything produced from these copies remains in the sandbox.

## 3. Run the complete automated test

From the host:

```sh
sbx exec \
  -w /home/emi/tmp/cargo-wrapper-dependency-audit \
  dependency-audit-complete-smoke \
  env CARGO_WRAPPER_SOURCE=/home/agent/cargowrapper-plugin-host \
  ./scripts/sbx-plugin-smoke.sh
```

The first run installs Debian build prerequisites and Rust 1.96.0, so it takes a few minutes. The helper then performs all of these checks:

1. Runs Cargo Wrapper’s own `wrapper-install` command inside SBX.
2. Confirms `cargo` resolves to `/home/agent/.local/bin/cargo`, while `rustc` remains the sandbox Rust toolchain.
3. Confirms `cargo wrapper` works and no plugins are initially installed.
4. Builds a clean project through Cargo Wrapper alone.
5. Confirms ordinary `cargo update` is rejected and `cargo forceupdate` succeeds.
6. Builds Dependency Audit and runs all its unit, protocol, middleware, and localhost security-POC tests inside SBX.
7. Repeats the accepted-risk POC with visible output, including the test-only `YOU COULD HAVE BEEN INFECTED!` banner.
8. Installs the plugin through `cargo wrapper plugin install`.
9. Confirms installation leaves the plugin inactive and that an inactive plugin is skipped.
10. Enables it explicitly and verifies protocol version, scanner version, approval path, and empty factory state.
11. Confirms directly executing the plugin binary fails because protocol v1 is required.
12. Confirms ordinary `cargo install` is rejected and immediately prints the complete scoped-bypass command.
13. Confirms `cargo forceinstall` without acknowledgement is also rejected before Cargo runs.
14. Uses `--accept-unreviewed-install-risk` to install a local sandbox-only fixture, verifies the prominent warning, and confirms the executable was installed.
15. Runs `cargo forceadd serde --features derive` against an empty approval store, exercises `V`, `F`, `C`, `D`, and `L`, chooses reject, and verifies rollback plus no saved approvals.
16. Generates the consolidated Markdown audit report and verifies its overall-verdict and non-execution instructions.
17. Verifies dump-only does not mutate the project or save approvals.
18. Verifies `--accept-all-once` performs the operation but persists no artifact or workspace state.
19. Verifies `--accept-and-remember-all` writes exact approvals and enables the approved-workspace fast path.
20. Rejects factory-bundle installation with the default answer and confirms no state was created.
21. Explicitly installs the 2,764-entry factory bundle and confirms its version in plugin status.
22. Repeats the exact graph rejected in step 15 and confirms it now proceeds without a prompt.
23. Approves `proc-macro2 1.0.104`, which is outside the factory snapshot, and verifies the personal approval is reused.
24. Disables the plugin and confirms Cargo Wrapper still works.
25. Uninstalls the plugin, confirms the plugin list is empty, and verifies plugin-owned approvals remain.

Successful output ends with:

```text
============================================================
COMPLETE DEPENDENCY AUDIT SBX TEST PASSED
============================================================
Cargo Wrapper worked alone; plugin inactive/active behavior worked.
Install rejection/bypass, evidence, links, LLM, dump, once, remember, factory, disable, and uninstall checks passed.
Plugin-owned approvals remained after uninstall, as designed.
```

## 4. Inspect the captured evidence

The automated run keeps its reports in the sandbox even though it uninstalls the plugin at the end. Reattach:

```sh
sbx run --name dependency-audit-complete-smoke
```

Inside SBX:

```sh
sed -n '1,240p' \
  "$HOME/dependency-audit-smoke-state/interactive-review.txt"

find "$HOME/dependency-audit-once-demo" \
  -maxdepth 1 -name 'audit-prompt-*.md' -print

sed -n '1,160p' \
  "$HOME/dependency-audit-once-demo"/audit-prompt-*.md

grep -c '^\[\[approvals\]\]' \
  "$HOME/dependency-audit-smoke-state/factory-approvals.toml"
```

The last command should print `2765`: 2,764 factory entries plus the deliberately remembered personal `proc-macro2 1.0.104` approval.

## 5. Optional manual interactive test

The automated test uninstalled the plugin, so reinstall and enable the already sandbox-built binary:

```sh
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
export CARGO_WRAPPER_PLUGIN_DIR="$HOME/manual-dependency-audit/plugins"

MANUAL_STATE=$(mktemp -d "$HOME/manual-dependency-audit.XXXXXX")
export CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE="$MANUAL_STATE/approvals.toml"

cargo wrapper plugin install dependency-audit \
  /home/emi/tmp/cargo-wrapper-dependency-audit/target/release/cargo-wrapper-plugin-dependency-audit
cargo wrapper plugin list
cargo wrapper plugin enable dependency-audit
cargo wrapper plugin list

"$HOME/.cargo/bin/cargo" init \
  --bin --name dependency-audit-manual \
  "$MANUAL_STATE/project"
cd "$MANUAL_STATE/project"
cargo forceadd serde --features derive
```

At the first prompt choose `I`. At an artifact finding, try:

- `V` for matched evidence;
- `F` and a file number for the complete verified file;
- `C` for the exact crates.io release;
- `D` for exact docs.rs documentation/source;
- `L` for the copy-ready, non-executing LLM prompt; and
- `R` to reject.

Then confirm rejection did not add `serde` or save approvals:

```sh
grep -q '^serde' Cargo.toml || echo 'GOOD: serde was not added'
test ! -e "$CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE" && \
  echo 'GOOD: no approvals were persisted'
```

Generate a consolidated report:

```sh
cargo forceadd serde --features derive --dump-audit-prompt
ls -1 audit-prompt-*.md
```

After an independent review, the two explicit batch decisions are:

```sh
cargo forceadd serde --features derive --accept-all-once
cargo forceadd serde --features derive --accept-and-remember-all
```

Use a new project for each command if you want to compare their state cleanly. `--accept-all-once` must not change the approval file. The remember form must add exact `[[approvals]]` records.

Factory trust remains a separate opt-in:

```sh
cargo dependency-audit trust-bundle show
cargo dependency-audit trust-bundle install
```

Press Enter first to verify default rejection; rerun and type `I` to install.

## 6. Disable, uninstall, and remove the sandbox

Inside SBX:

```sh
cargo wrapper plugin disable dependency-audit
cargo wrapper plugin uninstall dependency-audit
cargo wrapper plugin list
exit
```

On the host, delete only the named test sandbox:

```sh
sbx rm dependency-audit-complete-smoke
```

Confirm the prompt. This removes the sandbox Rust installation, wrapper, plugin, caches, projects, test logs, and approvals. Neither host repository is modified by sandbox removal.
