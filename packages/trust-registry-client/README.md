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
bind the bundle's first-signer DID method ID to the accepted epoch key-ID
commitment. They do not fetch a ledger, establish that the epoch was accepted,
authenticate the key's historical maintainer status, or check the ledger
contract format. A
relying party must establish those facts from a format-one registry ledger or
another independently trusted anchor before using the result as an
authorization decision. The `/simulator` testing subpath exports
`TrustRegistrySimulatorClient`, which binds these inputs to its simulator,
checks the bundle registry ID against the ledger commitment, uses that
commitment for signature verification, and rejects incompatible ledger formats
before evidence and raw
record reads, including when the ledger changes after client construction;
that simulator is a local reference, not a production trust source.

`verifyAuditorRequestMandate` additionally requires an explicit evaluation
time and a current auditor authorization record read from independently
trusted ledger state. An older active bundle remains valid as historical
evidence but cannot authorize a new audit request after suspension or
revocation. The simulator client reads that current record itself. Production
callers must not pass a cached record or derive it from the bundle under test.

`assertDecisionEvidenceDidMethodMatchesObservation` parses a DID Document with
the published Midnight DID package and matches the exact method, native JWK,
controller, role relationship, block, state version, and (for ledger
observations) transaction hash claimed by a decision evidence envelope. It
accepts same-document fragment references in a DID relationship only after
expanding them against the resolved document DID; a different fragment or
foreign DID cannot name the claimed method. It
also requires the observed DID state to be non-deactivated. The observation
must come from a caller-authenticated,
finalized DID-state source. The comparator does not validate a ledger proof or
establish finality and must not be used alone to produce a VC signer descriptor.
Claims labeled `state-proof` fail closed until a DID-ledger proof verifier is
implemented; only authenticated ledger observations are accepted in v1.

`assertDecisionEvidenceConsistentWithSuppliedContext` composes that DID check
with accepted-epoch equality, complete Compact publication signatures, exact
grant inclusion/policy/scope-preimage/window checks, and a jointly observed decision
sequence/evaluation time. It returns no descriptor. Callers must authenticate
that joint observation, including the active policy root and current grant at
the selected sequence, and the other supplied contexts, then establish
finality and currentness separately; Midnight does not bind sequence to time.

`verifyDecisionEvidenceWithTrustedReaders` takes an explicit caller-selected
role and scope, obtains the current finalized registry snapshot and DID state
from injected readers, runs those checks, and returns a role-discriminated
decision candidate only on success. It passes the claimed epoch ID merely as
a lookup hint; neither reader may copy an anchor from the candidate bundle or
answer from unfinalized/stale state. No production authenticated reader is
provided here, and the candidate is not a VC `AuthorizedSignerDescriptor` or
authority proof. Consumers must not provide fixture readers in production.
