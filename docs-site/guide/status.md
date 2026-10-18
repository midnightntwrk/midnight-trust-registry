# Status and limitations

The 0.1.0 reference profile is a **target**, not a release conformance claim. The current code is a local-first reference with a Compact contract, TypeScript domain/client packages, simulator journeys, a file-backed API, and UIs. Do not interpret a demo HTTP `202` as network finality.

| Capability | Current position |
| --- | --- |
| Issuer, verifier, auditor, maintainer lifecycle | Compact circuits and simulator/integration coverage; HTTP governed actions require injected ports |
| DID/VC application evidence | Midnight DID and VC/VP fixture-backed flows; private HTTP intake requires trusted application port |
| Maintainer signatures | Policy-bound JubJub Schnorr checked by Compact in simulator paths |
| Epoch and historical evidence | Commitments, bundles, query/client projections; caller must authenticate a finalized ledger anchor independently |
| External recognition | Scoped evidence and admission paths; no implicit federation or cross-registry authority |
| Packaged CLI service | Read/query ready from snapshot/workspace; no production DID resolver or Compact submission port by default |
| Production Midnight deployment | Not claimed by this documentation |
| Arbitrary DID methods and secp256k1/P-256/Ed25519 contract verification | Not implemented in Compact reference profile |

The canonical gap list and acceptance criteria live in the [milestone profile](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/spec/milestone-0.1.0.md), [issue plan](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/plans/milestone-0.1.0-issues.md), and [GitHub issues](https://github.com/midnightntwrk/midnight-trust-registry/issues). The [draft release-candidate note](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/guide/release-candidate-0.1.0.md) lists the exact qualification and owner decisions still needed. This site should be updated when code or the profile changes; it does not supersede the specifications.

## Security assumptions

- The operator snapshot/API is not a root of trust. Independently verify ledger state and decision evidence.
- A DID resolver must provide authentic historical method state for the observation time.
- Application VPs and claims remain private and off-ledger; only redacted commitments and receipts belong in the registry.
- The local file lock serializes same-host workspace writes, not distributed transactions.
- Status/revocation belongs to VC infrastructure; a registry grant alone cannot make a VC valid.
