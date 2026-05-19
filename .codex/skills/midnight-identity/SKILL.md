---
name: midnight-identity
description: "Use this skill for midnight-trust-registry work: trust-registry scope definition, DID/VC trust-policy boundaries, governance surfaces, workspace submodule integration, and develop-branch publication hygiene."
---

# Midnight Trust Registry Skill

Use this skill from `midnight-trust-registry` when shaping the trust-registry workstream used by the Midnight identity workspace.

## Required Context

1. Read `README.md`, `CONTRIBUTING.md`, and `SECURITY.md` first; this repo is still template-like and should be made concrete carefully.
2. If inside `midnight-identity-workspace`, read the workspace-root `AGENT.md` for submodule rules.
3. Align trust-registry changes with DID and VC integration boundaries: DID owns identifier resolution, VC owns credential/status semantics, this repo should own trust-policy and registry governance surfaces.

## Defaults

- Target branch is `develop` unless instructed otherwise.
- Use DCO/GPG for repository-facing commits: `git commit -S --signoff -m "<type>: <subject>"`.
- Avoid introducing source/package layout before the registry scope and validation targets are explicit.

## Current State

The repo currently has template community-health files and no package manifest. Keep changes documentation-first unless the task explicitly asks for implementation scaffolding.

## MCP

Use the Midnight MCP server as a helper for Compact/TypeScript package inspection in neighboring DID/VC repos, but do not commit personal MCP config.
