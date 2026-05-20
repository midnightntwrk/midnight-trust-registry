#!/usr/bin/env bash
set -euo pipefail

RUN_COMMON_TARGET="full"
RUN_COMMON_TARGET_KIND="wrapper"
RUN_COMMON_LIGHT="0"
RUN_COMMON_FORWARD_ARGS=()

run_common_target_exists() {
  local target="$1"

  case "${target}" in
    full|core|docs|integration|lint|typecheck|build|test|clean|clean-artifacts|help|targets|-h|--help)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

run_common_root_script_exists() {
  local script_name="$1"

  node -e '
    const scripts = require("./package.json").scripts ?? {};
    const name = process.argv[1];
    process.exit(Object.prototype.hasOwnProperty.call(scripts, name) ? 0 : 1);
  ' "${script_name}"
}

run_common_parse_args() {
  if [[ $# -gt 0 ]]; then
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
      RUN_COMMON_TARGET="$1"
      shift
    elif [[ "$1" != -* ]] && run_common_target_exists "$1"; then
      RUN_COMMON_TARGET="$1"
      shift
    elif [[ "$1" != -* ]] && run_common_root_script_exists "$1"; then
      RUN_COMMON_TARGET="$1"
      RUN_COMMON_TARGET_KIND="npm-script"
      shift
    fi
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --light)
        RUN_COMMON_LIGHT="1"
        shift
        ;;
      --)
        shift
        while [[ $# -gt 0 ]]; do
          RUN_COMMON_FORWARD_ARGS+=("$1")
          shift
        done
        ;;
      *)
        RUN_COMMON_FORWARD_ARGS+=("$1")
        shift
        ;;
    esac
  done
}

run_common_ensure_node() {
  if ! command -v node >/dev/null 2>&1; then
    echo "[run] node is required" >&2
    exit 1
  fi

  if ! command -v npm >/dev/null 2>&1; then
    echo "[run] npm is required" >&2
    exit 1
  fi
}

run_common_usage() {
  cat <<'EOF'
Usage:
  ./run.sh [target] [--light]
  ./run.sh <root-npm-script> [--light] [-- <script args...>]

Targets:
  full        Run the standard repository validation lane (default)
  core        Run the repository code-validation lane
  docs        Run documentation validation only
  integration Run integration scenarios
  lint        Run docs + lint checks
  typecheck   Run TypeScript checks
  build       Build package outputs
  test        Run unit tests
  clean       Remove build outputs
  clean-artifacts Alias for clean
  targets     Show this help

Options:
  --light     Run the light validation lane when supported
EOF
}

run_common_run_root_script() {
  echo "[run] Root npm script: ${RUN_COMMON_TARGET}"

  if [[ "${#RUN_COMMON_FORWARD_ARGS[@]}" -gt 0 ]]; then
    npm run "${RUN_COMMON_TARGET}" -- "${RUN_COMMON_FORWARD_ARGS[@]}"
  else
    npm run "${RUN_COMMON_TARGET}"
  fi
}
