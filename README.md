<!-- User guide for installing and operating the standalone Dependency Audit plugin. -->
# Cargo Wrapper Dependency Audit

Dependency Audit is an optional middleware plugin for the [Cargo Wrapper](https://github.com/danielemiliogarcia/cargowrapper) project forked from [Original Cargo Wrapper](https://github.com/jonasmartin/cargowrapper).

Before Cargo can download, compile, or execute newly resolved dependency source, it identifies exact remote artifacts and surfaces their build-time capabilities for explicit review.

The plugin is registered as `dependency-audit` and distributed as `cargo-wrapper-plugin-dependency-audit[.exe]`.

## What it protects

For Cargo operations routed through an enabled plugin, Dependency Audit provides:

- exact source, crate name, version, and checksum identities;
- isolated, index-only candidate resolution for dependency mutations;
- bounded in-memory `.crate` download and archive inspection after explicit authorization;
- checksum verification before source evidence is trusted;
- detection of build scripts, procedural macros, build-dependency closure, process execution, network access, filesystem mutation, environment/credential-like access, FFI, dynamic loading, shells, and downloaders;
- default-deny interactive decisions: reject, accept once, or remember the exact artifact;
- candidate-versus-final lock comparison and workspace rollback on failure or divergence;
- optional copy-ready LLM prompts and batch audit reports;
- an optional exact-artifact factory trust bundle.

Checksum mismatch, malformed archives, unsupported dependency sources, and inspection failures cannot be overridden.

## Threat model and limitations

This is a guardrail for Cargo calls that pass through Cargo Wrapper. It is not an operating-system sandbox and static analysis cannot prove source safe. A developer, IDE, plugin, or tool that invokes real Cargo directly can bypass it. Path dependencies are local code rather than immutable registry artifacts, and new or changed Git dependencies fail closed instead of being cloned before review.

Plugins are native programs that run with your privileges. Verify this plugin's source and release provenance before enabling it. A GitHub artifact attestation establishes which repository and workflow produced an artifact; it does not prove the source is harmless.

Protocol v1 orders plugins alphabetically. Dependency Audit uses `CARGO_WRAPPER_REAL_CARGO` for private isolated candidate resolution, which later plugins cannot intercept. A policy that must wrap Dependency Audit needs a registration name sorting before `dependency-audit`, such as `age-policy`.

## Requirements

- Cargo Wrapper with executable plugin protocol v1.
- A supported precompiled release target:
  - `aarch64-apple-darwin`
  - `aarch64-unknown-linux-gnu`
  - `x86_64-apple-darwin`
  - `x86_64-unknown-linux-gnu`
  - `x86_64-pc-windows-msvc`

The protocol contract is documented in [PLUGIN-PROTOCOL.md](https://github.com/danielemiliogarcia/cargowrapper/blob/fork-main/PLUGIN-PROTOCOL.md).

## Install a verified precompiled binary

Precompiled releases are preferred because building the plugin from source would make Cargo download and compile the plugin's own dependencies before this protection is available.

If you prefer to build from source after reviewing and auditing the code, or because you do not trust the published binary, perform the bootstrap build in an isolated, disposable sandbox. This contains the risk from dependencies that Cargo must fetch and compile before the plugin is available to protect later operations. A sandbox limits exposure to the host, but it does not replace dependency review, checksum verification, or reproducible-build comparison.

1. Pin an exact release version and inspect its source and release notes.
2. Download the archive for your platform from that release.
3. Verify its checksum and GitHub artifact attestation against this repository and `.github/workflows/release.yml`.
4. Extract the archive.
5. Register the local binary. Core installation deliberately leaves it inactive.
6. Inspect the installed state, then explicitly enable it.

Linux and macOS:

```sh
version=v0.1.0
archive=cargo-wrapper-dependency-audit-x86_64-unknown-linux-gnu.tar.xz
directory=${archive%.tar.xz}

gh attestation verify "$archive" \
  --repo danielemiliogarcia/cargo-wrapper-dependency-audit \
  --signer-workflow danielemiliogarcia/cargo-wrapper-dependency-audit/.github/workflows/release.yml
sha256sum --check "$archive.sha256"
tar -xJf "$archive"

cargo wrapper plugin install dependency-audit \
  "./$directory/cargo-wrapper-plugin-dependency-audit"
cargo wrapper plugin list
cargo wrapper plugin enable dependency-audit
cargo wrapper plugin list
```

On macOS, use `shasum -a 256` if `sha256sum` is unavailable and select the Apple target matching the machine.

Windows PowerShell:

```powershell
$Archive = "cargo-wrapper-dependency-audit-x86_64-pc-windows-msvc.zip"
$ExtractRoot = ".\dependency-audit"
$Directory = Join-Path $ExtractRoot ([IO.Path]::GetFileNameWithoutExtension($Archive))
gh attestation verify $Archive `
  --repo danielemiliogarcia/cargo-wrapper-dependency-audit `
  --signer-workflow danielemiliogarcia/cargo-wrapper-dependency-audit/.github/workflows/release.yml
$Actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
$Expected = ((Get-Content "$Archive.sha256") -split '\s+')[0].ToLowerInvariant()
if ($Actual -ne $Expected) { throw "archive checksum mismatch" }
Expand-Archive $Archive -DestinationPath $ExtractRoot

cargo wrapper plugin install dependency-audit `
  (Join-Path $Directory "cargo-wrapper-plugin-dependency-audit.exe")
cargo wrapper plugin list
cargo wrapper plugin enable dependency-audit
cargo wrapper plugin list
```

The core host does not download, inspect, execute, update, or automatically enable the binary during installation.

## Status and configuration

When enabled:

```sh
cargo dependency-audit
```

This prints the plugin, protocol, and scanner versions; approval path; and installed factory-bundle version.

Personal exact approvals default to:

- Linux/macOS: `$XDG_CONFIG_HOME/cargo-wrapper-dependency-audit/approvals.toml`, or `$HOME/.config/cargo-wrapper-dependency-audit/approvals.toml`.
- Windows: `%APPDATA%\CargoWrapperDependencyAudit\approvals.toml`.

Override the file with `CARGO_WRAPPER_DEPENDENCY_AUDIT_APPROVAL_FILE`. Set `CARGO_WRAPPER_DEPENDENCY_AUDIT_VERBOSE` for fast-path diagnostics. Approval TOML is parsed strictly as data and malformed content fails closed.

## Interactive dependency review

Commands that can change dependency resolution require their reviewed form:

```sh
cargo forcegenerate-lockfile
cargo forceadd <dependency-name> --features <feature-name>
cargo forceremove <dependency-name> # compatibility alias
cargo remove <dependency-name>      # also reviewed directly
cargo forceupdate                   # core rewrites this to the reviewed update path
```

Direct `cargo install` is rejected because Cargo installation downloads and compiles a separate package and its dependency graph, but the plugin cannot currently resolve and review that complete graph without first allowing Cargo to download unreviewed source. Even when you trust the requested package, its current transitive dependencies, build scripts, or procedural macros could be compromised and execute with your user privileges. The rejection immediately prints the complete command for the scoped bypass:

```sh
cargo forceinstall --accept-unreviewed-install-risk <package-name>
```

Without that flag, `cargo forceinstall` repeats the explanation and remains blocked. With it, the plugin displays a prominent warning, removes its private flag, and forwards `cargo install --locked <package-name>` to the remaining plugin chain. This one-time bypass does not inspect the installation graph or create approvals. Prefer performing an unreviewed installation in an isolated, disposable sandbox. `cargo forceadd` is not an alternative because it adds a dependency to the current project instead of installing an executable.

When source inspection is needed, the first prompt asks whether the plugin may download each `.crate` into bounded private memory. It will not cache, extract, compile, macro-expand, analyze with rust-analyzer, dynamically load, interpret, or execute that source.

For each finding:

- `V`: show matched code evidence.
- `F`: show complete relevant file from the verified in-memory archive.
- `C`: print exact crates.io link.
- `D`: print exact docs.rs and source links.
- `L`: print copy-ready read-only LLM audit prompt.
- `R` or Enter: reject.
- `O`: accept once for this transaction.
- `W`: accept and remember the exact artifact/checksum/finding set.

Evidence and links are advisory and return to the default-deny decision prompt.

## Batch audit workflow

Create one report without changing the workspace, calling downstream Cargo, or saving approvals:

```sh
cargo forceadd <dependency-name> --features <feature-name> --dump-audit-prompt
```

Give the printed file to an LLM or coding agent using the exact handoff printed by the plugin. The report requires read-only web review, treats crate-controlled text as hostile, prohibits execution, and requires one overall `ACCEPT_ALL` or `REJECT` verdict. The plugin never calls an LLM and never consumes its verdict automatically.

After independently accepting the report, rerun resolution and inspection with one of:

```sh
cargo forceadd <dependency-name> --features <feature-name> --accept-all-once
cargo forceadd <dependency-name> --features <feature-name> --accept-and-remember-all
```

Compare every printed exact identity with the earlier report because resolution may have changed.

## Optional factory trust bundle

The embedded bundle is inert until explicitly installed:

```sh
cargo dependency-audit trust-bundle show
cargo dependency-audit trust-bundle install
```

Installation requires a default-deny confirmation and imports only exact versions and checksums bound to the current scanner version. It does not authorize older versions by range. Future releases, checksum changes, yanked or excluded artifacts, and unlisted crates still require review. See [FACTORY-SCAN.md](FACTORY-SCAN.md) for the cumulative scan provenance and exclusions.

To use an empty factory set, simply never install the bundle. Personal interactive approvals continue independently.

## Disable, uninstall, and purge

```sh
cargo wrapper plugin disable dependency-audit
cargo wrapper plugin uninstall dependency-audit
```

Core uninstall removes only the installed executable and deliberately retains approvals. To intentionally purge them after disabling/uninstalling, remove only the applicable plugin-owned directory listed in “Status and configuration,” or the exact override file you configured.

## Security POCs

The test suite uses only a synthetic crate served by a loopback-only registry. It proves both boundaries:

```text
rejected finding → downstream never invoked → no canary
accepted finding → downstream invoked → synthetic build.rs creates PWNED_CANARY
```

Run with visible output:

```sh
cargo test --test security_poc -- --nocapture
```

The conspicuous `YOU COULD HAVE BEEN INFECTED!` banner is test-only and explicitly says it is a localhost synthetic POC.

## Development

```sh
cargo fmt --all --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

Build local release artifacts with pinned cargo-dist using [scripts/install-pinned-dist.sh](scripts/install-pinned-dist.sh), then:

```sh
dist build --artifacts=local --output-format=json
```

See [RELEASING.md](RELEASING.md).

## License and extraction history

MIT licensed; see [LICENSE](LICENSE).
