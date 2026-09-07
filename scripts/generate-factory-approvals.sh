#!/usr/bin/env bash
# Audits current lockfiles plus prior approvals, then regenerates the cumulative factory bundle.
# Pass --reset to discard prior approvals; generated files are written to this repository.

set -euo pipefail

reset=false
if [[ ${1:-} == "--reset" ]]; then
    reset=true
    shift
fi
if [[ $# -ne 1 ]]; then
    printf 'usage: %s [--reset] <source-root>\n' "$0" >&2
    exit 2
fi

source_root=$1
if [[ ! -d "$source_root" ]]; then
    printf 'error: source root is not a directory: %s\n' "$source_root" >&2
    exit 1
fi

for required_command in cargo cargo-audit jq; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf 'error: required command is unavailable: %s\n' "$required_command" >&2
        exit 1
    fi
done

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
blocklist="$work_dir/blocked-identities.tsv"
: > "$blocklist"

lockfiles=("$repository_root/Cargo.lock")
while IFS= read -r -d '' discovered_lockfile; do
    if [[ "$discovered_lockfile" != "$repository_root/Cargo.lock" ]]; then
        lockfiles+=("$discovered_lockfile")
    fi
done < <(
    find "$source_root" \
        \( -type d \( -name .git -o -name target -o -name vendor \) -prune \) -o \
        \( -type f -name Cargo.lock -print0 \)
)

scan_options=()
factory_bundle="$repository_root/factory-approvals.toml"
if [[ $reset == false && -f "$factory_bundle" ]]; then
    previous_lock="$work_dir/previous-factory-approvals.lock"
    cargo run --release --locked --example scan_factory_bundle -- \
        --write-bundle-lock "$factory_bundle" "$previous_lock"
    lockfiles+=("$previous_lock")
    scan_options+=(--existing-bundle "$factory_bundle")
    printf 'Append mode: retaining and revalidating exact identities from %s\n' \
        "$factory_bundle"
else
    printf 'Reset mode: generating only from current lockfile inventory\n'
fi
if [[ ${#lockfiles[@]} -eq 0 ]]; then
    printf 'error: no Cargo.lock files found beneath %s\n' "$source_root" >&2
    exit 1
fi

printf 'Auditing %d lockfiles with the current RustSec database...\n' "${#lockfiles[@]}"
for index in "${!lockfiles[@]}"; do
    lockfile=${lockfiles[$index]}
    audit_json="$work_dir/audit-$index.json"
    audit_stderr="$work_dir/audit-$index.stderr"
    audit_options=(--json --file "$lockfile")
    if [[ $index -gt 0 ]]; then
        audit_options+=(--no-fetch)
    fi

    # Findings make cargo-audit exit nonzero. A valid JSON report is still required.
    cargo audit "${audit_options[@]}" > "$audit_json" 2> "$audit_stderr" || true
    if ! jq -e . "$audit_json" >/dev/null 2>&1; then
        printf 'error: cargo-audit did not produce valid JSON for %s\n' "$lockfile" >&2
        sed -n '1,20p' "$audit_stderr" >&2
        exit 1
    fi

    jq -r '
        (
          .vulnerabilities.list[]? |
          ["vulnerability", (.advisory.id // ""), .package.name,
           (.package.version | tostring), (.package.checksum // "")]
        ),
        (
          (.warnings // {}) | to_entries[]? | .key as $category | .value[]? |
          [$category, (.advisory.id // ""), .package.name,
           (.package.version | tostring), (.package.checksum // "")]
        ) | @tsv
    ' "$audit_json" >> "$blocklist"
done

LC_ALL=C sort -u -o "$blocklist" "$blocklist"

cd "$repository_root"
cargo run --release --locked --example scan_factory_bundle -- \
    "${scan_options[@]}" \
    "$repository_root" \
    "$source_root" \
    "$blocklist" \
    factory-approvals.toml \
    FACTORY-SCAN.md

printf 'Generated %s and %s\n' \
    "$repository_root/factory-approvals.toml" \
    "$repository_root/FACTORY-SCAN.md"
