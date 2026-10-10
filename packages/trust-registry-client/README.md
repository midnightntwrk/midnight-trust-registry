# Trust Registry Client

TypeScript client helpers for querying and validating trust-registry state.

Current scope:

- raw current and historical queries against the local simulator/contract surface
- temporal helpers that answer lifecycle and trust state at a specific timestamp
- evidence-bundle verification for issuer, verifier, and recognition decisions
- epoch-anchor verification against published roots and maintainer signatures
- consumer-side verification exercised by simulator, DID-backed, and VC-backed
  integration scenarios
- a Midnight DID observation comparator for versioned decision evidence

This package is the consumer-facing layer on top of the Compact contract.

For challenge-backed application proposals, `scopeCommitment` means the
canonical `tr-scope-v1` authorization-scope digest, not a hash of the governed
resource ID. The resource ID remains a separate proposal input. The
integration simulator derives this same scope digest for its test fixtures;
its deterministic challenge values must not be treated as applicant evidence.

The exported free `verify*Bundle` functions verify a bundle against a
caller-supplied epoch record, maintainer key, and registry commitment. They do
not fetch a ledger, establish that the epoch was accepted, authenticate the
key's historical maintainer status, or check the ledger contract format. A
relying party must establish those facts from a format-one registry ledger or
another independently trusted anchor before using the result as an
authorization decision. The `/simulator` testing subpath exports
`TrustRegistrySimulatorClient`, which binds these inputs to its simulator,
checks the bundle registry ID against the ledger commitment, uses that
commitment for signature verification, and rejects incompatible ledger formats
before evidence and raw
record reads, including when the ledger changes after client construction;
that simulator is a local reference, not a production trust source.

`assertDecisionEvidenceDidMethodMatchesObservation` parses a DID Document with
the published Midnight DID package and matches the exact method, native JWK,
controller, role relationship, block, state version, and (for ledger
observations) transaction hash claimed by a decision evidence envelope. It
also requires the observed DID state to be non-deactivated. The observation
must come from a caller-authenticated,
finalized DID-state source. The comparator does not validate a ledger proof or
establish finality and must not be used alone to produce a VC signer descriptor.
