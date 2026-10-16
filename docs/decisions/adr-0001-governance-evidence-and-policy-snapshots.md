# ADR-0001: Governance Evidence And Policy Snapshots

Status: accepted

Date: 2026-07-27

## Context

Trust decisions must remain interpretable after a policy update, key rotation,
or maintainer membership change. The registry already has signer bundles and
policy commitments, but it needs one historical interpretation for application
evidence and quorum execution.

## Decision

- Signer-set commitments are canonical and order independent. Sort the 32-byte
  maintainer key-ID commitments as unsigned little-endian integers before
  submitting a signer bundle. Compact verifies strict ordering, distinctness,
  and zero padding before hashing. The first slot is the lowest key ID, not a
  privileged vote or proof of transaction submission. A transaction submitter
  must be authenticated separately by the transport when that identity matters.
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
- With two or more active maintainers, every configured threshold MUST be
  below the active count, and a removal MUST leave the same headroom. The
  target cannot sign its own active suspension, revocation, or archival.
  A 2-of-3 policy needs one old-quorum-signed atomic recovery action to
  suspend the target and install a valid 1-of-2 policy. A separate revision
  to 1-of-3 followed by removal exposes a target-controlled interval. The
  single-maintainer bootstrap case retains threshold one and the last-active
  removal prohibition. A separate recovery authority is deferred; no
  emergency bypass can be inferred from a surviving key.
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

Maintainer signatures all cover the same deployment-bound action digest, so
sorting their signed entries does not change what each signer approved. The
fixed-capacity bundle contains one to five active signers followed by zero
padding. Both the contract and publication-evidence client enforce the same
order; `lastAuthorizedMaintainerKeyId` and the accepted epoch's first-signer
field identify the lowest signer key ID, not the transaction submitter.
This amends the original byte-lexicographic draft: Compact compares two exact
128-bit limbs rather than unrolling a costly 32-byte comparison fold.
On the pinned Compact 0.31.1 compiler, `--skip-zk` serialized 65 ZKIR circuits
at 8,842,084 bytes before this rule and 11,223,309 bytes after it. The
`publishEpochCommitment` ZKIR grew from 199,395 to 257,616 bytes. These are
compiler-output size measurements, not proving-time or key-size measurements;
full artifact and integration qualification remains a release gate.

Canonical two-signer example: `signer1 = 0x80` followed by 31 zero bytes,
`signer2 = 31 zero bytes` followed by `0x01`, and signer slots 3-5 all zero.
Little-endian ordering puts `signer1` first; the Compact
`maintainerSignerSetHash(2, signer1, signer2, 0, 0, 0)` is
`0xa2a083e62cd7a8c2e3dcca00448fc2b20c4e59e295cdbbedbdd3f34f74430d80`.
Reversing the two signed entries is rejected before event creation, rather
than producing a second historical event hash for the same quorum.

## Rejected Alternatives

- Preserve signer order as policy meaning: rejected because approval order is
  not a governance property and complicates reproducibility.
- Parse VC/VP formats in Compact: rejected because it increases circuit cost,
  binds the contract to evolving encodings, and risks private-data leakage.
- Let an evidence verifier activate an applicant directly: rejected because it
  bypasses registry governance.
