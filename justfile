set shell := ["bash", "-euo", "pipefail", "-c"]

default: check

status:
    git status --short --branch

check: docs-check whitespace-check light-check

whitespace-check:
    git diff --check
    if git rev-parse --verify HEAD~1 >/dev/null 2>&1; then git diff --check HEAD~1..HEAD; fi

docs-check:
    ./scripts/check-docs.sh

light-check:
    ./run.sh --light
