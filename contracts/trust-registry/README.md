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

The initial contract format (version 1) stores the
canonical V1 policy snapshot digest supplied at
bootstrap. A threshold revision atomically records the next digest and version
in the same signed action, and epoch publication accepts only a committed
digest effective at the epoch's `validFromSequence`. Every governed action
signature and event now binds the policy digest active at its sequence; the
ledger also exposes the digest used by the last authorized action. Compact
records a revised policy as effective at the next action sequence, because
the revision action itself was signed under the previous policy. Compact
signs and stores the digest; clients must independently recompute it from the
disclosed policy record. The 0.1.0 reference path is a fresh deployment;
prototype policy-ID roots, signatures, and event hashes are not valid evidence
for this format. The format-one marker does not make an older prototype with
the same numeric marker compatible; consumers must check the actual ledger
shape and verification-key provenance as well.
All governed action signing and verification uses the policy-bound helpers
with the active 32-byte policy commitment; no unbound signing API is exposed.
Issuer, verifier, auditor, and recognition records enter the ledger through
separate proposal, authorization, and activation actions. The prototype
direct-create entry points are not part of format one.

For epoch publication, the epoch record persists the submitter
(`signer1`) key id, signature, and policy commitment active at publication.
That commitment can differ from `policyRoot` when an older epoch is published
after a policy revision. Verify the signature against the publication
commitment; use `policyRoot` to interpret the epoch's historical window. The
full approving quorum is bound into the governance-event chain through the
signer-set hash.
