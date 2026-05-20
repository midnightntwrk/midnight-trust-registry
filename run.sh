#!/usr/bin/env bash
set -euo pipefail

source ./scripts/run-common.sh

run_common_parse_args "$@"

case "${RUN_COMMON_TARGET}" in
  help|targets|-h|--help)
    run_common_usage
    exit 0
    ;;
esac

run_common_ensure_node

if [[ "${RUN_COMMON_TARGET_KIND}" == "npm-script" ]]; then
  run_common_run_root_script
  exit 0
fi

case "${RUN_COMMON_TARGET}" in
  full)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      npm run ci:build:light
    else
      npm run ci:build
    fi
    ;;
  core)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      npm run ci:build:light
    else
      npm run ci:build
    fi
    ;;
  docs)
    npm run docs-check
    ;;
  lint)
    npm run ci:lint
    ;;
  typecheck)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      npm run typecheck:light
    else
      npm run typecheck
    fi
    ;;
  build)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      npm run build:light
    else
      npm run build
    fi
    ;;
  test)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      npm run test:light
    else
      npm run test
    fi
    ;;
  clean)
    npm run clean
    ;;
  clean-artifacts)
    npm run clean:artifacts
    ;;
  integration)
    echo "[run] No integration lane is defined yet for this repository."
    exit 0
    ;;
  *)
    echo "[run] Unknown target: ${RUN_COMMON_TARGET}" >&2
    run_common_usage >&2
    exit 1
    ;;
esac
