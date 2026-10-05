# Midnight Trust Registry

`midnight-trust-registry` owns the trust-policy and registry-governance workstream for Midnight identity. It defines how issuers, verifiers, credential resources, and external authorities become trusted without moving DID resolution or verifiable credential issuance into this repository.

The repository contains a simulator-first contract, client, API, and local app
skeleton. The 0.1.0 milestone turns that foundation into a DID/VC-backed,
governed reference journey without duplicating the sibling repositories'
responsibilities.

## Scope

This repository owns:

- Trust registry governance and policy records.
- Issuer, verifier, schema, and credential-definition authorization state.
- Recognition of external authorities and registries.
- Historical evidence needed for long-term credential verification.
- Query and evidence surfaces that applications can consume.
- Compact and TypeScript packages for registry contracts, clients, and adapters.

This repository does not own:

- DID document resolution or DID CRUD operations. Those belong in `midnight-did`.
- VC, VP, claim, holder-binding, or credential-status semantics. Those belong in `midnight-verifiable-credentials`.
- Revocation/status registries. The first TR implementation should integrate with the VC status registry instead of cloning it.

## Documentation Map

- [0.1.0 reference profile](docs/spec/milestone-0.1.0.md) defines the actor,
  use-case, security, and release-acceptance contract for the next milestone.
- [0.1.0 executable issue plan](docs/plans/milestone-0.1.0-issues.md) maps
  each use case to a tracker issue, dependency, and definition of done.
- [Trust registry specification](docs/spec/trust-registry.md) defines the v1 product and protocol scope.
- [Implementation plan](docs/plans/trust-registry-implementation-plan.md) breaks execution into reviewable slices.
- [Execution backlog](docs/plans/trust-registry-backlog.md) tracks the current maturity backlog.
- [Requirements memo](docs/research/trust-registry-requirements-memo.md) captures the research inputs used to derive the requirements.
- [Architecture boundaries](docs/architecture/trust-registry-boundaries.md) describes how TR integrates with DID and VC repositories.
- [Demo and release guide](docs/guide/demo-and-release.md) documents the operator walkthrough, package boundaries, and manual publish/smoke workflows.
- [Decisions](docs/decisions/trust-registry-decisions.md) records current design decisions and unresolved questions.

## Development Baseline

Target branch is `develop`.

Use signed DCO commits for repository-facing changes:

```bash
git commit -S -s -m "<type>: <subject>"
```

Current local validation baseline:

```bash
pnpm install --frozen-lockfile
./run.sh --light
```

`.compact-version` is the single Compact compiler version pin for the Nix
toolchain and all Compact GitHub workflows. The light gate checks every
top-level workflow that directly installs Compact, plus Nix; add a future
Compact-installing composite action to this guard. To upgrade, change that file, update the
platform-specific fetch hashes in `nix/packages/compact-toolchain.nix`, then
run `pnpm run check:compact-version` and `./run.sh --light`. Validate the
toolchain itself with `nix develop --command compactc --version` and
`nix develop --command ./run.sh --light` before opening a PR. The contract
build wrapper passes the pin explicitly as `+VERSION`; an unqualified
`compact compile` can select a different host-installed default. A host-installed
`compact` outside the Nix shell must also match this pin for `./run.sh --light`
to pass; use the Nix shell if the host installation differs.

Integration scenarios currently run separately:

```bash
./run.sh integration
```

The fast GitHub CI lane also runs the focused DID/VC scenarios after
`./run.sh --light`:

```bash
pnpm --filter @midnight-ntwrk/trust-registry-integration run integration
```

Package artifact validation for downstream consumers:

```bash
pnpm run artifacts:pack
pnpm run packages:check-contents
pnpm run packed-artifacts:smoke
```

Artifact tarballs are written to `artifacts/npm/`. The current local artifact
set is:

- `@midnight-ntwrk/trust-registry-contract`
- `@midnight-ntwrk/trust-registry-domain`
- `@midnight-ntwrk/trust-registry-client`
- `@midnight-ntwrk/trust-registry-integration`
- `@midnight-ntwrk/trust-registry-cli`
- `@midnight-ntwrk/trust-registry-api`
- `@midnight-ntwrk/trust-registry-trqp-adapter`
- `@midnight-ntwrk/trust-registry-openid-federation-adapter`

The remotely publishable core package subset is intentionally narrower:

- `@midnight-ntwrk/trust-registry-contract`
- `@midnight-ntwrk/trust-registry-domain`
- `@midnight-ntwrk/trust-registry-client`
- `@midnight-ntwrk/trust-registry-trqp-adapter`
- `@midnight-ntwrk/trust-registry-openid-federation-adapter`

`@midnight-ntwrk/trust-registry-integration`, `@midnight-ntwrk/trust-registry-cli`,
and `@midnight-ntwrk/trust-registry-api` remain local-only artifacts for now
while their public packaging and deployment policy is finalized. Identity
dependencies are installed from npm; local artifact smoke runs in a clean
consumer without seeding vendored dependency tarballs.

## Quick Demo Workflow

Prepare a mutable local operator workspace from the repo root:

```bash
pnpm run demo:prepare
```

Then start the local surfaces in separate terminals:

```bash
pnpm run demo:serve:api
pnpm run demo:serve:admin-console
pnpm run demo:serve:applicant-portal
```

Default local endpoints:

- API: `http://127.0.0.1:4400`
- Admin console: `http://127.0.0.1:4173`
- Applicant portal: `http://127.0.0.1:4175`

You can also seed a deterministic read-only snapshot for fixture-driven demos:

```bash
pnpm run demo:prepare:snapshot
```

Smoke-test the documented demo flow from a clean local checkout:

```bash
pnpm run demo:smoke
```

Refresh published DID and VC dependencies with validation:

```bash
pnpm run refresh:identity-dependencies -- --did-version 0.7.0 --vc-version 0.2.0 --validate light
```

For docs-only edits, the minimum fallback remains:

```bash
./scripts/check-docs.sh
git diff --check
```

## Project Files

- [Contributing guide](CONTRIBUTING.md) describes the contribution process.
- [Security policy](SECURITY.md) describes responsible disclosure.
- [License](LICENSE) is Apache-2.0.
- [Code owners](CODEOWNERS) defines repository ownership.

## Current Package Surface

Implemented now:

```text
packages/trust-registry-domain/  TypeScript domain records, lifecycle validators, and evidence schemas
contracts/trust-registry/        Compact governance, authorization, recognition, and epoch contract
packages/trust-registry-integration/  Local simulator harness and end-to-end trust scenarios
packages/trust-registry-client/  TypeScript query and evidence-verification client
packages/trust-registry-cli/     Operator CLI for local workspace initialization, governed participant workflows, snapshot inspection, evidence export, and audit reports
packages/trust-registry-api/     HTTP query and governed-application surface over saved snapshots and operator workspaces
packages/trust-registry-admin-console/  Local admin review UI for governed approval, lifecycle actions, and epoch publication
packages/trust-registry-applicant-portal/  Local applicant submission and public active-registry inspection UI
adapters/trqp/                   TRQP-style read adapter
adapters/openid-federation/      OpenID Federation publication experiment
```

## Planned Additions

The next package layout is intentionally narrow:

```text
examples/                         DID/VC integration examples
```

Do not create the remaining directories until the corresponding backlog item is implemented with tests and docs.
