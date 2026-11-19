#!/usr/bin/env bash
set -euo pipefail

output="${1:?reference output directory required}"
mkdir "$output"
gh api repos/midnightntwrk/midnight-trust-registry/actions/artifacts/14494787037/zip > "$output/reference.zip"
printf '%s  %s\n' '22cf2ec8dd4b41dd641a574add195db53177c3b7dfebd0a15b6d6a52bfb7d4c9' "$output/reference.zip" | sha256sum --check
unzip -q "$output/reference.zip" -d "$output"
