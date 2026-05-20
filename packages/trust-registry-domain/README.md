# `@midnight-ntwrk/trust-registry-domain`

Typed domain model for `midnight-trust-registry`.

This package owns:

- canonical identifiers and hash helpers
- registry, policy, participant, authorization, recognition, and epoch record
  schemas
- lifecycle transition validators
- the first canonical evidence-bundle schema and JSON schema export

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
- `assertLifecycleTransition`

