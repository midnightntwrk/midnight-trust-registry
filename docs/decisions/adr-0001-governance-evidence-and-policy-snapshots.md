# ADR-0001: Governance Evidence And Policy Snapshots

Status: accepted

Date: 2026-07-27

## Context

Trust decisions must remain interpretable after a policy update, key rotation,
or maintainer membership change. The registry already has signer bundles and
policy commitments, but it needs one historical interpretation for application
evidence and quorum execution.

## Decision

- Signer-set commitments are canonical and order independent. Sort active
  maintainer key identifiers lexicographically before hashing or evaluating a
  signer bundle. The submitter is recorded separately and has no extra voting
  power.
- A policy version is immutable. A governed event binds `policyId`,
  `policyVersion`, its policy commitment, and the threshold family used by the
  decision. Later policy versions never reinterpret earlier events.
- An evidence verifier is a policy-authorized authority with a DID and
  assertion key reference. Its attestation proves off-chain VC/VP verification;
  maintainers still decide whether the application becomes authorized or
  active.
- Ordinary approvals use the default maintainer threshold. Maintainer
  onboarding uses the membership threshold. Suspension/revocation uses the
  emergency threshold. Archival uses the archival threshold.
- A transition that would leave fewer active maintainers than its live
  threshold MUST fail. Recovery requires a separately defined emergency policy
  and cannot be implied by a single surviving key.
- Bootstrap initializes maintainers and policy state. Issuer, verifier,
  auditor, and recognition membership use proposal, approval, and activation;
  none has a direct-create exception.

## Consequences

Historical evidence can explain both who approved a decision and which policy
they applied. The Compact contract needs policy-version and evidence-verifier
references in addition to the existing threshold and signer-set commitment.
The 0.1.0 reference profile starts with a fresh deployment; no earlier
registry format has been released or is accepted as equivalent evidence.

## Canonical domain snapshot (0.1.0 slice)

The domain package now exports `deriveGovernancePolicySnapshot`,
`canonicalizeGovernancePolicySnapshot`, and
`computeGovernancePolicySnapshotCommitment`. V1 snapshots commit the registry
and policy IDs, monotonically increasing `vN` version, UTC-normalized effective
window, an independently computed policy-content digest, and sorted action
family thresholds. `maintainer`, `member`, and optional `auditor` thresholds
must agree because the current Compact contract enforces one default threshold
for all three; emergency and archival thresholds may differ. The content digest covers URI, templates, bindings, and
decision/dispute/retention/emergency rules; it excludes mutable lifecycle
status and event roots. Sets and family lists are sorted and duplicates are
rejected. All thresholds must fit the current Compact five-signer ceiling.
Consumers with the source policy record MUST call
`assertGovernancePolicySnapshotMatchesRecord` rather than trusting a supplied
`contentCommitment` by shape alone. A superseded policy record requires an
explicit `effectiveUntil`; a zero-length
window remains representable when the boundary is explicit.
V1 snapshot timestamps allow no more than millisecond precision: extra
fractional digits are rejected rather than silently truncated by JavaScript
`Date`. Records with versions outside monotonic `vN` notation or fewer than
the four required decision families are invalid for this reference profile.

For the example registry, four ordinary/membership/emergency/archival families
at 2-of-3 have this canonical snapshot vector when the content digest is
`0x` followed by 64 lowercase `a` characters:

```json
{"contentCommitment":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","effectiveFrom":"2026-10-05T00:00:00.000Z","effectiveUntil":null,"format":"tr-policy-snapshot-v1","policyId":"policy:kanon","policyVersion":"v1","registryId":"registry:midnight:kanon","thresholds":[{"family":"archival","threshold":2},{"family":"emergency","threshold":2},{"family":"maintainer","threshold":2},{"family":"member","threshold":2}]}
```

Its SHA-256 commitment is
`0x29485cb6d7192cdc2d70a9843fb2f3364ffadaa0e2de5a8f839db40b15b9852c`.
The domain helper rejects a revision that reuses a policy version or overlaps
the prior effective window. It also rejects a maintainer transition that
would leave fewer active maintainers than any configured threshold.

The current contract stores the policy snapshot commitment and binds governed
action signatures and event evidence to the commitment effective at the action
sequence. The contract does not validate the off-chain policy preimage;
consumers must recompute the snapshot digest from the policy record. Broader
application-evidence lifecycle work remains open under issue #75.

## Rejected Alternatives

- Preserve signer order as policy meaning: rejected because approval order is
  not a governance property and complicates reproducibility.
- Parse VC/VP formats in Compact: rejected because it increases circuit cost,
  binds the contract to evolving encodings, and risks private-data leakage.
- Let an evidence verifier activate an applicant directly: rejected because it
  bypasses registry governance.
