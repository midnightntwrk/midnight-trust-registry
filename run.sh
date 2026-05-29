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

if [[ "${RUN_COMMON_TARGET_KIND}" == "package-script" ]]; then
  run_common_run_root_script
  exit 0
fi

case "${RUN_COMMON_TARGET}" in
  full)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      pnpm run ci:build:light
    else
      pnpm run ci:build
    fi
    ;;
  core)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      pnpm run ci:build:light
    else
      pnpm run ci:build
    fi
    ;;
  docs)
    pnpm run docs-check
    ;;
  lint)
    pnpm run ci:lint
    ;;
  typecheck)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      pnpm run typecheck:light
    else
      pnpm run typecheck
    fi
    ;;
  build)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      pnpm run build:light
    else
      pnpm run build
    fi
    ;;
  test)
    if [[ "${RUN_COMMON_LIGHT}" == "1" ]]; then
      pnpm run test:light
    else
      pnpm run test
    fi
    ;;
  clean)
    pnpm run clean
    ;;
  clean-artifacts)
    pnpm run clean:artifacts
    ;;
  integration)
    pnpm run integration
    ;;
  *)
    echo "[run] Unknown target: ${RUN_COMMON_TARGET}" >&2
    run_common_usage >&2
    exit 1
    ;;
esac
