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

Contract version 3 stores the canonical V1 policy snapshot digest supplied at
bootstrap. A threshold revision atomically records the next digest and version
in the same signed action, and epoch publication accepts only a committed
digest effective at the epoch's `validFromSequence`. Every governed action
signature and event now binds the policy digest active at its sequence; the
ledger also exposes the digest used by the last authorized action. Compact
records a revised policy as effective at the next action sequence, because
the revision action itself was signed under the previous policy. Compact
signs and stores the digest; clients must independently recompute it from the
disclosed policy record. Contract-version-1 policy-ID roots cannot be
interpreted as snapshot digests. Version-2 signatures and event hashes are
not version-3 evidence. Existing deployments need a separately governed
migration or a new version-3 deployment before publishing this evidence.

For epoch publication, the epoch record persists the submitter
(`signer1`) key id, signature, and policy commitment active at publication.
That commitment can differ from `policyRoot` when an older epoch is published
after a policy revision. Verify the signature against the publication
commitment; use `policyRoot` to interpret the epoch's historical window. The
full approving quorum is bound into the governance-event chain through the
signer-set hash.
