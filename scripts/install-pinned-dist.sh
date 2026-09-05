#!/bin/sh
# Installs the exact checksum-pinned dist executable used by this repository's release workflow.
# The Docker Sandbox smoke helper uses it before building local distributables inside the sandbox.

set -eu

dist_version=0.32.0
install_dir=${DEPENDENCY_AUDIT_DIST_BIN_DIR:-"$HOME/.cargo/bin"}

if [ -x "$install_dir/dist" ] \
    && [ "$("$install_dir/dist" --version)" = "cargo-dist $dist_version" ]; then
    printf 'Reusing checksum-pinned cargo-dist %s\n' "$dist_version"
    exit 0
fi

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64 | Linux/amd64)
        target=x86_64-unknown-linux-gnu
        expected=eb52f9fae0d0506774e9f1801c1168f87fa2c87a45e2d64d3ae7c89401929946
        ;;
    Linux/aarch64 | Linux/arm64)
        target=aarch64-unknown-linux-gnu
        expected=d29bcffeb3f8b0c517b4ce0dd2470926ed5cb0bb29d78c6bdd5f88d76ee14a6a
        ;;
    *)
        printf 'error: unsupported pinned-dist host: %s/%s\n' "$(uname -s)" "$(uname -m)" >&2
        exit 1
        ;;
esac

archive="cargo-dist-${target}.tar.xz"
url="https://github.com/axodotdev/cargo-dist/releases/download/v${dist_version}/${archive}"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/dependency-audit-dist.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM

printf 'Downloading cargo-dist %s for %s\n' "$dist_version" "$target"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    "$url" --output "$work_dir/$archive"

actual=$(sha256sum "$work_dir/$archive" | cut -d ' ' -f 1)
if [ "$actual" != "$expected" ]; then
    printf 'error: cargo-dist archive checksum mismatch\n' >&2
    printf 'expected: %s\nactual:   %s\n' "$expected" "$actual" >&2
    exit 1
fi

tar -xJf "$work_dir/$archive" -C "$work_dir"
dist_binary=$(find "$work_dir" -type f -name dist -print -quit)
if [ -z "$dist_binary" ]; then
    printf 'error: dist executable is missing from its verified archive\n' >&2
    exit 1
fi

mkdir -p "$install_dir"
install -m 0755 "$dist_binary" "$install_dir/dist"
"$install_dir/dist" --version
