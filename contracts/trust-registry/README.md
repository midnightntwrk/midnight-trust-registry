# Trust Registry Contract

Minimal Compact contract package for the Midnight trust registry.

Current scope:

- registry initialization
- bootstrap maintainer registration
- generic maintainer authorization with fixed-capacity quorum bundles
- quorum-signed policy snapshot revisions with versioned digest history and
  default, emergency, and archival thresholds
- issuer authorization lifecycle and scope queries
- verifier authorization lifecycle and scope queries
- recognition lifecycle and scope queries
- epoch-anchor publication and current/by-id lookup

The current quorum implementation supports up to `5` maintainer signers per
action bundle so the contract can cover `3-of-5` and `5-of-7` governance
shapes without dynamic arrays. Historical lookup by timestamp, richer
governance policy bindings, and client-facing mutation/query adapters still
stack on top of this package.

Contract version 2 stores the canonical V1 policy snapshot digest supplied at
bootstrap. A threshold revision atomically records the next digest and version
in the same signed action, and epoch publication accepts only a committed
digest effective at the epoch's `validFromSequence`. Compact signs and stores
the digest; clients must independently recompute it from the disclosed policy
record. Contract-version-1 policy-ID roots cannot be interpreted as snapshot
digests. Existing deployments need a separately governed migration or a new
version-2 deployment before publishing V1 snapshot evidence.

For epoch publication, the epoch record persists the submitter
(`signer1`) key id and signature, while the full approving quorum is bound into
the governance-event chain through the signer-set hash.
