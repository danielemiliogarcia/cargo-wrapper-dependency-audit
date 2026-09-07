# Releasing Dependency Audit

Releases use checksum-pinned `cargo-dist` 0.32.0 and GitHub Actions. A version tag builds native archives on Linux, macOS, and Windows, creates checksums and a source archive, attests every published file, and creates the GitHub Release. The project deliberately does not generate an installer: users verify and extract an archive, then register its binary with Cargo Wrapper's plugin manager.

## Release targets

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

The matrix is defined in `dist-workspace.toml`. Each archive contains `cargo-wrapper-plugin-dependency-audit[.exe]`, `README.md`, and `LICENSE`. It never contains a binary named `cargo`.

## Build a host archive locally

Install the repository-pinned executable, then inspect and build the current host target:

```sh
./scripts/install-pinned-dist.sh
dist --version                 # cargo-dist 0.32.0
dist plan
dist build --artifacts=host --tag=v0.1.0
```

Use the version from `Cargo.toml`. Add `--allow-dirty` only for a local smoke test; never publish a dirty build because its binary and Git-derived source archive can represent different trees. Artifacts appear in `target/distrib/`, with names such as:

```text
cargo-wrapper-dependency-audit-x86_64-unknown-linux-gnu.tar.xz
cargo-wrapper-dependency-audit-x86_64-unknown-linux-gnu.tar.xz.sha256
source.tar.gz
source.tar.gz.sha256
sha256.sum
```

Verify them from `target/distrib`:

```sh
sha256sum --check cargo-wrapper-dependency-audit-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum --check source.tar.gz.sha256
tar -tJf cargo-wrapper-dependency-audit-x86_64-unknown-linux-gnu.tar.xz
```

A single host cannot produce all native artifacts. To assemble a release manually, run `dist build --artifacts=local` on suitable Linux, macOS, and Windows machines, collect the outputs, then run `dist build --artifacts=global`. The GitHub workflow automates this matrix.

## Cut a release

1. Update the package version in `Cargo.toml` and `Cargo.lock`.
2. Run:

   ```sh
   cargo test --all-targets --locked
   cargo clippy --all-targets --locked -- -D warnings
   cargo fmt --all --check
   dist plan
   ```

3. Review the plan, commit the release, and push a matching annotated tag:

   ```sh
   git tag -a v0.1.0 -m "Dependency Audit 0.1.0"
   git push origin v0.1.0
   ```

The workflow publishes only tags shaped like `vMAJOR.MINOR.PATCH`. Any verification, build, packaging, or attestation failure prevents publication.

## Release trust model

The workflow does not use `curl | sh` to bootstrap `dist`. The local action downloads the exact 0.32.0 executable and verifies a repository-pinned SHA-256 digest. External GitHub Actions are pinned to full commits, and the publishing job has the only attestation identity-token permission.

After downloading an artifact, verify both its checksum and repository provenance:

```sh
gh attestation verify \
  cargo-wrapper-dependency-audit-x86_64-unknown-linux-gnu.tar.xz \
  --repo danielemiliogarcia/cargo-wrapper-dependency-audit \
  --signer-workflow danielemiliogarcia/cargo-wrapper-dependency-audit/.github/workflows/release.yml
```

Checksums detect corruption and attestations identify the producing repository/workflow. Neither proves the source safe. macOS code signing and Windows Authenticode are not currently configured.

## Update `cargo-dist` or release actions

Treat release-infrastructure changes as security-sensitive:

1. Review the upstream release and immutable source revision.
2. Update `cargo-dist-version` in `dist-workspace.toml`, `DIST_VERSION` in `.github/actions/install-dist/action.yml`, and `dist_version` in `scripts/install-pinned-dist.sh` together.
3. Independently verify and update every platform digest in both installer helpers.
4. Update action commit hashes in `dist-workspace.toml` and the workflow together.
5. Run `dist plan` and review the generated workflow difference. Preserve the checksum-verifying bootstrap.

## Update the optional trust bundle

`factory-approvals.toml` is embedded but inert until the user explicitly runs `cargo dependency-audit trust-bundle install`.

Regenerate it from the widest source root containing the Cargo projects whose exact locked artifacts should be trusted:

```sh
./scripts/generate-factory-approvals.sh /path/to/source-root
```

Generation is cumulative by default. Existing exact identities are combined with the current lockfile inventory, checked again against the current RustSec database, checksum-verified, and rescanned before the output is replaced. This preserves previously reviewed coverage without preserving an identity that now fails validation.

Transient registry failures are retried with bounded exponential backoff. If any archive still cannot be downloaded or strictly inspected, generation aborts before replacing the existing bundle or report. Resolve the failure and rerun; never publish a bundle made smaller by unavailable scan input.

Each successful run appends its scope and exclusions to `FACTORY-SCAN.md`. Keep this cumulative history with the generated bundle; generation never truncates an earlier scan record.

To deliberately discard all previous identities and rebuild only from current lockfiles, use the explicit destructive mode:

```sh
./scripts/generate-factory-approvals.sh --reset /path/to/source-root
```

Always review the resulting exact-identity diff. A large unexpected deletion should block the release.

1. Use exact lockfile identities: source, name, version, and checksum.
2. Run `cargo audit` with a fresh RustSec database and exclude vulnerable, unsound, unmaintained, and yanked releases.
3. Run `examples/scan_factory_bundle.rs`; it verifies archives and uses the plugin's bounded memory-only scanner.
4. Fail closed for unavailable archives, conflicts, unsupported Git sources, or unresolved manifests. Record exclusions.
5. Manually review findings, update `bundle_version` and `reviewed_at`, and bind records to the current scanner version.
6. Keep each release checksum-exact. Never replace versions with ranges, wildcards, or SemVer ceilings.
7. Run all tests and both sandbox paths: no bundle installed, then an explicitly installed bundle.

Installing or updating the plugin must never import a trust bundle automatically.
