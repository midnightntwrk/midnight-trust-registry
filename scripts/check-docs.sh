#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

required_files=(
  "README.md"
  "AGENT.md"
  "docs/README.md"
  "docs/spec/trust-registry.md"
  "docs/plans/trust-registry-implementation-plan.md"
  "docs/plans/trust-registry-backlog.md"
  "docs/research/trust-registry-requirements-memo.md"
  "docs/decisions/trust-registry-decisions.md"
  "docs/architecture/trust-registry-boundaries.md"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "missing required documentation file: $file" >&2
    exit 1
  fi
done

python3 - <<'PY'
from pathlib import Path
from urllib.parse import unquote
import re
import sys

root = Path.cwd()
markdown_files = sorted(
    path for path in root.rglob("*.md")
    if ".git" not in path.parts
)

link_re = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
problems: list[str] = []
for path in markdown_files:
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(root)
    if "/Users/" in text or "\\Users\\" in text:
        problems.append(f"{rel}: contains machine-local absolute path")
    if "obsidian" in text.lower():
        problems.append(f"{rel}: contains private notes/vault reference")
    if "TODO - New Repo Owner" in text or "REPLACE WITH REPO-NAME" in text:
        problems.append(f"{rel}: contains template placeholder")
    for match in link_re.finditer(text):
        raw_target = match.group(1).strip()
        if not raw_target or raw_target.startswith("#"):
            continue
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw_target):
            continue
        target = raw_target.split("#", 1)[0]
        if not target:
            continue
        target = unquote(target)
        resolved = (path.parent / target).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            problems.append(f"{rel}: link escapes repository: {raw_target}")
            continue
        if not resolved.exists():
            problems.append(f"{rel}: broken link: {raw_target}")

if problems:
    print("documentation check failed:", file=sys.stderr)
    for problem in problems:
        print(f"- {problem}", file=sys.stderr)
    sys.exit(1)
PY

echo "documentation check passed"
