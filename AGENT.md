# AGENT

Engineering guide for agents and engineers working in `midnight-trust-registry`.

This repository can be cloned independently or as a submodule of `midnight-identity-workspace`. When it is inside the workspace, apply the workspace-root `AGENT.md` first, then this file.

## Purpose

`midnight-trust-registry` owns Midnight trust policy, registry governance, issuer/verifier authorization, external authority recognition, and historical evidence surfaces. It exists to integrate with DID and VC packages without taking over their responsibilities.

## Repository Boundary

Use this repository for:

- Registry governance policy and lifecycle state.
- Maintainer, issuer, verifier, and authority authorization.
- Recognition of external registries or authorities.
- Historical evidence bundles and epoch commitments.
- Query surfaces for trust decisions.
- Future Compact contracts, TypeScript clients, and registry adapters.

Do not use this repository for:

- DID CRUD, DID document normalization, resolver behavior, or wallet/key management. Use `midnight-did`.
- VC/VP data model, claim representation, holder binding, credential status, revocation, or credential-family semantics. Use `midnight-verifiable-credentials`.
- Holder personal data or presentation activity logs.
- Revocation accumulator state. Integrate with the VC status registry instead.

## Current Layout

```text
docs/spec/          Product and protocol specifications
docs/plans/         Execution plans and backlog
docs/research/      Public research-derived requirements
docs/decisions/     Design decisions and open questions
                     plus repo-local execution knowledge
docs/architecture/  Repo boundaries and integration diagrams
packages/           TypeScript workspaces for registry domain and clients
scripts/            Local validation helpers
run.sh              Repository entrypoint for light/full validation
```

Current source layout:

```text
packages/trust-registry-domain/
```

Planned follow-on layout:

```text
contracts/trust-registry/
packages/trust-registry-client/
packages/trust-registry-testing/
adapters/trqp/
adapters/openid-federation/
examples/
```

Create planned directories only when implementing the corresponding backlog slice with tests and docs.

## Working Cycle

1. Sync from `origin/develop`.
2. Create a `codex/` branch for agent-authored work unless the user asks for a different prefix. Human contributors can keep following the contributor guide's personal-prefix convention.
3. Keep PRs large enough to deliver a real improvement and narrow enough to review.
4. Run local validation before commit.
5. Commit with DCO and GPG.
6. Push and open PRs against `develop` or the previous branch when stacking.
7. Ask for second-opinion review when the change affects protocol, governance, package layout, Compact contracts, CI, or security boundaries.

Commit form:

```bash
git commit -S -s -m "<type>: <subject>"
```

## Validation

Minimum validation for docs-only changes:

```bash
./scripts/check-docs.sh
git diff --check
```

`./scripts/check-docs.sh` requires `python3`.

If `just` is available:

```bash
just check
```

Current code baseline:

```bash
npm ci
./run.sh --light
```

## Midnight MCP

For MCP-capable clients, configure the Midnight MCP server at user level. Do not commit personal MCP configuration or tokens. The example below uses Codex TOML syntax; adapt the same command and args for clients that use JSON configuration.

```toml
[mcp_servers.midnight]
command = "npx"
args = ["-y", "midnight-mcp@latest"]
```

Use MCP as a navigation helper for Compact and TypeScript package surfaces, but validate with local scripts and CI.

## Public Documentation Rules

- Do not commit private notes, local vault paths, local wallet state, proof-server logs, or absolute machine-specific paths.
- Convert research notes into public requirements and cite public references where available.
- Keep authorization and recognition separate in docs and code.
- Keep status/revocation separate from trust-governance state.

## Knowledge Base Maintenance

Maintain TR knowledge at three levels:

1. repo-local:
   - `docs/decisions/trust-registry-knowledge-base.md`
2. workspace-root:
   - `midnight-identity-workspace/research/`
3. global:
   - the `trusted-registry` Obsidian vault

Update all three when a meaningful implementation slice lands, a branch/PR
strategy changes, or the architectural direction materially changes.
