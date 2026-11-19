#!/usr/bin/env bash
set -euo pipefail

output="${1:?artifact output directory required}"
run_id="${2:?prepare run ID required}"
revision="${3:?source revision required}"
artifact="$(node scripts/resolve-keyless-prepare-run.mjs "$GITHUB_REPOSITORY" "$run_id" "$revision")"
artifact_id="$(jq -er '.id' <<< "$artifact")"
digest="$(jq -er '.sha256' <<< "$artifact")"
mkdir "$output"
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT
gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id/zip" > "$archive"
printf '%s  %s\n' "$digest" "$archive" | sha256sum --check
unzip -Z1 "$archive" | node --input-type=module -e '
  let list = "";
  for await (const chunk of process.stdin) list += chunk;
  const paths = list.trimEnd().split("\n");
  const valid = /^(?:[a-z0-9][a-z0-9.-]*\.tgz|cache-receipt\.json|key-regeneration\.json|npm-release\.manifest\.json|SHA256SUMS)$/u;
  if (paths.length !== 14 || new Set(paths).size !== paths.length || !paths.every((p) => valid.test(p))) {
    throw new Error("Unexpected keyless release archive entries");
  }
'
unzip -q "$archive" -d "$output"
printf 'Verified preparation run %s artifact %s SHA-256 %s\n' "$run_id" "$artifact_id" "$digest"
