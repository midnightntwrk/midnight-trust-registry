---
name: midnight-identity
description: "Use this skill for midnight-trust-registry work: trust-registry scope definition, DID/VC trust-policy boundaries, governance surfaces, workspace submodule integration, and develop-branch publication hygiene."
---

# Midnight Trust Registry Skill

Use this skill from `midnight-trust-registry` when shaping the trust-registry workstream used by the Midnight identity workspace.

## Required Context

1. Read `AGENT.md`, `README.md`, `CONTRIBUTING.md`, and `SECURITY.md` first.
2. If inside `midnight-identity-workspace`, read the workspace-root `AGENT.md` for submodule rules.
3. Align trust-registry changes with DID and VC integration boundaries: DID owns identifier resolution, VC owns credential/status semantics, this repo owns trust-policy and registry governance surfaces.

## Defaults

- Target branch is `develop` unless instructed otherwise.
- Use DCO/GPG for repository-facing commits: `git commit -S -s -m "<type>: <subject>"`.
- Keep changes documentation-first until the package or contract slice has explicit validation.
- Run `./scripts/check-docs.sh` for docs-only changes.

## PR Gate (required before any PR)

- Required workspace gate:
  - `cd <workspace-root>/midnight-identity-workspace && ./run.sh --light --repos trust-registry`
  - `cd <workspace-root>/midnight-identity-workspace && ./run.sh --light --strict --repos did`
- Repo-local minimum:
  - `./run.sh --light`
  - `./run.sh integration`
  - `./run.sh lint`
- Do not open PRs until this gate passes.

## MCP

Use the Midnight MCP server as a helper for Compact/TypeScript package inspection in neighboring DID/VC repos, but do not commit personal MCP config.
