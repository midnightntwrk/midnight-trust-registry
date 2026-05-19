# Midnight Trust Registry

`midnight-trust-registry` owns the trust-policy and registry-governance workstream for Midnight identity. It defines how issuers, verifiers, credential resources, and external authorities become trusted without moving DID resolution or verifiable credential issuance into this repository.

The repository is intentionally documentation-first while the contract and package boundaries are being finalized. The first implementation target is a registry that works with `midnight-did` and `midnight-verifiable-credentials` without duplicating their responsibilities.

## Scope

This repository owns:

- Trust registry governance and policy records.
- Issuer, verifier, schema, and credential-definition authorization state.
- Recognition of external authorities and registries.
- Historical evidence needed for long-term credential verification.
- Query and evidence surfaces that applications can consume.
- Future Compact and TypeScript packages for registry contracts, clients, and adapters.

This repository does not own:

- DID document resolution or DID CRUD operations. Those belong in `midnight-did`.
- VC, VP, claim, holder-binding, or credential-status semantics. Those belong in `midnight-verifiable-credentials`.
- Revocation/status registries. The first TR implementation should integrate with the VC status registry instead of cloning it.

## Documentation Map

- [Trust registry specification](docs/spec/trust-registry.md) defines the v1 product and protocol scope.
- [Implementation plan](docs/plans/trust-registry-implementation-plan.md) breaks execution into reviewable slices.
- [Execution backlog](docs/plans/trust-registry-backlog.md) tracks the current maturity backlog.
- [Requirements memo](docs/research/trust-registry-requirements-memo.md) captures the research inputs used to derive the requirements.
- [Architecture boundaries](docs/architecture/trust-registry-boundaries.md) describes how TR integrates with DID and VC repositories.
- [Decisions](docs/decisions/trust-registry-decisions.md) records current design decisions and unresolved questions.

## Development Baseline

Target branch is `develop`.

Use signed DCO commits for repository-facing changes:

```bash
git commit -S -s -m "<type>: <subject>"
```

For now, documentation-only changes are validated with:

```bash
git diff --check
```

Follow-up PRs will add repository-local validation commands before source packages are introduced.

## Project Files

- [Contributing guide](CONTRIBUTING.md) describes the contribution process.
- [Security policy](SECURITY.md) describes responsible disclosure.
- [License](LICENSE) is Apache-2.0.
- [Code owners](CODEOWNERS) defines repository ownership.

## Expected Package Direction

The planned package layout is intentionally narrow:

```text
contracts/trust-registry/       Compact contract surface for governance and authorization state
packages/trust-registry-domain/   TypeScript domain model, codecs, and policy validators
packages/trust-registry-client/   Read/write client adapters for apps and tests
packages/trust-registry-testing/  Fixtures and conformance helpers
adapters/trqp/                    ToIP TRQP-compatible query adapter
adapters/openid-federation/       OpenID Federation metadata/trust-chain adapter
examples/                         DID/VC integration examples
```

Do not create these directories until the corresponding backlog item is implemented with tests and docs.
