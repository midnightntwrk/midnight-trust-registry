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

- [Documentation site](docs-site/index.md) explains the reference implementation,
  actors, contract, API, flows, and limitations; the GitHub Pages workflow
  publishes it from `develop`.
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
- [Standalone local journey quickstart](docs/guide/standalone-local-journey.md) separates real offline deployment evidence from simulator tests and lists the operator stop gates.
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

For documentation changes, run `./run.sh docs` to check links, validate the
OpenAPI inventory, and build the site. Use `pnpm run docs:dev` for local preview.

`.compact-version` is the single Compact compiler version pin for the Nix
toolchain and all Compact GitHub workflows. The light gate checks every
top-level workflow that directly installs Compact, plus Nix; add a future
Compact-installing composite action to this guard. To upgrade, change that file, update the
platform-specific fetch hashes in `nix/packages/compact-toolchain.nix`, then
run `pnpm run check:compact-version` and `./run.sh --light`. Validate the
toolchain itself with `nix develop --command compactc --version` and
`nix develop --command ./run.sh --light` before opening a PR. The contract
build wrapper passes the pin explicitly as `+VERSION`; an unqualified
`compact compile` can select a different host-installed default. The light
gate also checks that unqualified compiler default, so a host-installed
`compact` outside the Nix shell must match the pin for `./run.sh --light` to
pass. Use the Nix shell if the host default differs.

For local simulator iterations, run the same integration suites and demo smoke
journeys without generating proving keys:

```bash
./run.sh integration --light
```

Before publishing contract or demo changes, run the full integration lane.
It generates proving keys and remains the validation gate for those artifacts:

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
pnpm run packages:check-contents:light
pnpm run packed-artifacts:smoke
```

After a full `pnpm run build`, use `pnpm run packages:check-contents` instead;
the release gate requires proving keys and ZK IR in the contract package.

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

For the separate, fixture-only auditor applicant journey, run
`pnpm run demo:auditor` and open `http://127.0.0.1:4400`. This serves the
portal and its private API on one loopback origin. Paste the DID-signed
application printed by the command, issue a challenge, then generate the
matching VP in another terminal with
`node scripts/demo-auditor-admission.mjs vp <nonce>` and paste its JSON into
the portal. `pnpm run demo:auditor:smoke` automates that same HTTP path and
checks unauthorized access, wrong scope, and replay. The host uses a fixture
identity, in-memory state, and a fixed virtual clock; it is not a public
admission service or a production VC status verifier.

`pnpm run demo:signed-issuer`, `pnpm run demo:signed-verifier`,
`pnpm run demo:signed-auditor`, and `pnpm run demo:signed-maintainer` run the same joined local membership journey
for each role. The harness derives
registration preflight and API snapshots from one Compact simulator, then
serves public queries from a fresh private file-backed operator workspace.
Only the host's governed epoch-publication port updates that workspace from
the simulator projection. It acquires the local workspace lock before Compact
execution, so a competing process gets 409 without advancing governance.
The demo then starts a separate read-only API process against the same file to
check that the final epoch and historical/current decisions survive restart.
Unsafe fixture mutation routes remain disabled. It
exercises DID-signed application, one-use VP, redacted receipt, 2-of-3
maintainer proposal/approval/activation, and externally signed registry epoch
publication through the admin console API client. The publish route rejects
a stale context or insufficient quorum before accepting a ledger commitment;
the public epoch lookup then observes that exact commitment. The issuer,
verifier, and auditor paths then use the same signed quorum to suspend and
revoke the grant, reject single or duplicate signers, deny current trust,
and preserve the earlier active decision. The maintainer path likewise
suspends and revokes its non-bootstrap member and checks the active governor
count in Compact. Issuer,
verifier, and auditor grants reach an API bundle independently verified by the
client; maintainer activation is checked in Compact. Single-maintainer actions cannot advance
the ledger. Pending records, consumed nonces, challenges, and accepted redacted
receipts use private files that a second store instance can reopen. The local
journeys use the applicant portal client for the signed application and VP
admission, and the admin console client for quorum proposal and lifecycle
actions. Issuer and verifier journeys compare the public API trust decision
and evidence leaf with TRQP at the same selected time; auditor has no TRQP
mapping in this profile. `./run.sh integration --light` executes all four
joined journeys as the deterministic local CI target. The local
file adapter does not make challenge consumption, evidence acceptance, and
Compact governance one atomic transaction; the demo does not establish
production family/status verification or network finality.
Per-grant evidence snapshots still use simulator fixture signing; the
externally signed route covers registry epoch publication, not every evidence
bundle created during projection.
The auditor grant proves an exact request-profile mandate; it does not grant
automatic access to a verifier's private records.
The maintainer journey verifies activation in the Compact membership record;
it does not claim a public issuer-style authorization bundle.

Refresh published DID and VC dependencies with validation:

```bash
pnpm run refresh:identity-dependencies -- --did-version 0.7.0 --vc-version 0.2.0 --validate light
```

`pnpm run check:workspace-manifests` validates checked-in manifests before
dependencies are installed. After `pnpm install`, run
`pnpm run check:installed-identity-runtime` to verify the effective DID/VC
packages, pnpm overrides, and resolved Compact runtime. The light gate runs
both checks in that order.

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
