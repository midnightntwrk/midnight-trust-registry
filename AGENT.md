# AGENT

Engineering guide for agents and engineers working in `midnight-trust-registry`.

This repository can be cloned independently or as a submodule of
`midnight-identity-workspace`. When it is inside the workspace, apply the
workspace-root `AGENT.md` first, then this file.

## Purpose

`midnight-trust-registry` owns Midnight trust policy, registry governance,
issuer/verifier authorization, external authority recognition, and historical
evidence surfaces. It exists to integrate with DID and VC packages without
taking over their responsibilities.

The repository is expected to work both as a standalone clone and inside the
workspace shell. `nix develop` should provide the local baseline toolchain for
Compact, Node.js, pnpm/Turbo workflows, and helper commands.

## Quick Start

Prerequisites:

- Node.js 24
- Midnight Compact toolchain
- `pnpm`
- Nix when working from the identity workspace

Standalone setup:

```bash
pnpm install
```

Nix shell:

```bash
nix develop
```

Fast validation:

```bash
./run.sh --light
```

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

## Package Map

| Path | Package | Responsibility |
| --- | --- | --- |
| `contracts/trust-registry` | `@midnight-ntwrk/trust-registry-contract` | Compact contract, generated managed artifacts, and contract-facing TS helpers. |
| `packages/trust-registry-domain` | `@midnight-ntwrk/trust-registry-domain` | Registry state model, lifecycle rules, policy/evidence types, and canonical hashing inputs. |
| `packages/trust-registry-client` | `@midnight-ntwrk/trust-registry-client` | Query helpers, evidence verification, and consumer-facing trust decision APIs. |
| `packages/trust-registry-integration` | `@midnight-ntwrk/trust-registry-integration` | DID/VC-aware simulator and integration scenarios across repository boundaries. |
| `packages/trust-registry-cli` | `@midnight-ntwrk/trust-registry-cli` | Local operator workflows, demo setup, audit reporting, and mutable workspace actions. |
| `packages/trust-registry-api` | `@midnight-ntwrk/trust-registry-api` | Read/query and governed workflow HTTP surface for local operator and applicant flows. |
| `packages/trust-registry-admin-console` | `@midnight-ntwrk/trust-registry-admin-console` | Operator-facing review and administration UI. |
| `packages/trust-registry-applicant-portal` | `@midnight-ntwrk/trust-registry-applicant-portal` | Applicant-facing UI for issuer/verifier/auditor submissions. |
| `adapters/trqp` | `@midnight-ntwrk/trust-registry-trqp-adapter` | TRQP-compatible registry and evidence projection. |
| `adapters/openid-federation` | `@midnight-ntwrk/trust-registry-openid-federation-adapter` | OpenID Federation metadata and trust-chain projection experiments. |

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
packages/trust-registry-client/
packages/trust-registry-integration/
contracts/trust-registry/
adapters/trqp/
adapters/openid-federation/
```

Planned follow-on layout:

```text
examples/
```

Create planned directories only when implementing the corresponding backlog slice with tests and docs.

## Compact and Generated Source Rules

Important source files:

- `contracts/trust-registry/src/trust-registry.compact`
- `contracts/trust-registry/src/**/*.ts`
- `packages/**/src/**`
- `adapters/**/src/**`

Generated outputs:

- `contracts/trust-registry/src/managed/**`
- `contracts/trust-registry/dist/**`
- `packages/*/dist/**`
- `adapters/*/dist/**`
- `coverage/**`
- `reports/**`
- `*.tsbuildinfo`

Do not manually edit generated outputs. Regenerate them through package build
or compact scripts, then validate the generated surface through tests.

## Development Cycle

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
pnpm install --frozen-lockfile
./run.sh --light
./run.sh integration
```

Useful additional forms:

```bash
./run.sh docs
./run.sh lint
./run.sh build --light
./run.sh test --light
just check
```

For contract or managed-artifact changes, ensure the light lane passes from a
clean tree after regenerating outputs.

## Nix and Shell Notes

- `nix develop` should provide `compact`, `compactc`, `node`, `pnpm`, `turbo`,
  `just`, `docker`, and `oras`.
- The shell exports `COMPACT_DIRECTORY` so Compact package scripts can locate
  the compiler toolchain without host-specific setup.
- `.envrc` inherits parent workspace shell context through `source_up` and
  enables signed commits locally.

## Midnight MCP

For MCP-capable clients, configure the Midnight MCP server at user level. Do not commit personal MCP configuration or tokens. The example below uses Codex TOML syntax; adapt the same command and args for clients that use JSON configuration.

```toml
[mcp_servers.midnight]
command = "npx"
args = ["-y", "midnight-mcp@latest"]
```

Use MCP as a navigation helper for Compact and TypeScript package surfaces, but validate with local scripts and CI.

## Agent Surface

This `AGENT.md` is the canonical repository-local agent guide for Codex,
Claude, and pi.dev-style agent runners. Keep it aligned with `.codex/` and
`.claude/` helper files when validation gates, branch strategy, or repository
boundaries change.

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
