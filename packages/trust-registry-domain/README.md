# `@midnight-ntwrk/trust-registry-domain`

Typed domain model for `midnight-trust-registry`.

This package owns:

- canonical identifiers and hash helpers
- registry, policy, participant, authorization, recognition, and epoch record
  schemas
- lifecycle transition validators
- the first canonical evidence-bundle schema and JSON schema export
- a separate strict `tr-decision-evidence-v1` envelope schema and JSON Schema

This package does not own:

- Compact contracts
- DID resolution
- VC or status verification logic

Primary exports:

- `createScopedIdentifier`
- `sha256Hex`
- `LifecycleStatusSchema`
- `AuthorizationRecordSchema`
- `RecognitionRecordSchema`
- `TrustRegistryEvidenceBundleSchema`
- `TrustRegistryEvidenceBundleJsonSchema`
- `DecisionEvidenceSchema`
- `DecisionEvidenceJsonSchema`
- `assertLifecycleTransition`

`DecisionEvidenceSchema` is structural only. Its epoch and DID anchor references
are untrusted lookup claims, not independently accepted anchors. A successful
parse does not authenticate signatures, Merkle paths, DID state, policy
currency, or signer authorization, and it does not produce a VC descriptor.
The existing single-signature evidence bundle remains unchanged. Cross-field
consistency checks in Zod (including declared quorum size and the `uint64`
range) are not expressible in the exported JSON Schema; consumers must parse
with Zod before attempting the later independent verification stages.
Ledger and DID state versions use canonical decimal `uint64` strings, not JSON
numbers, so values above JavaScript's safe-integer limit are not truncated.
