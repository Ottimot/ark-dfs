#!/usr/bin/env bash
set -euo pipefail

# Run ONCE on the author's machine with the known working nightly installed.
# Commit the generated rust-toolchain.toml; other users only need Docker.
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain="${1:-nightly}"
sysroot="$(rustc "+${toolchain}" --print sysroot)"
manifest="${sysroot}/lib/rustlib/multirust-channel-manifest.toml"
output="${project_dir}/rust-toolchain.toml"

if [[ -e "$output" ]]; then
    echo "Already exists: $output. Review it before selecting another toolchain." >&2
    exit 1
fi
if [[ ! -r "$manifest" ]]; then
    echo "Cannot read the installed Rustup distribution manifest: $manifest" >&2
    echo "Choose and verify a dated nightly manually; do not guess from the commit date." >&2
    exit 1
fi

compiler_info="$(rustc "+${toolchain}" --version --verbose)"
if [[ "$compiler_info" != *"release: "*"-nightly"* ]]; then
    echo "Expected a nightly toolchain, got: $toolchain" >&2
    exit 1
fi

# Read the top-level distribution date, before any TOML table.
distribution_date="$(awk -F '"' '
    /^[[:space:]]*\[/ { exit }
    /^[[:space:]]*date[[:space:]]*=/ { print $2; exit }
' "$manifest")"
if [[ ! "$distribution_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "Could not determine the distribution date from $manifest" >&2
    exit 1
fi

cat > "$output" <<EOF
[toolchain]
channel = "nightly-${distribution_date}"
profile = "minimal"
EOF

echo "$compiler_info"
echo "Created $output with nightly-${distribution_date}. Commit this file."
