set shell := ["bash", "-euo", "pipefail", "-c"]

default: check

status:
    git status --short --branch

check: docs-check
    git diff --check

docs-check:
    ./scripts/check-docs.sh
