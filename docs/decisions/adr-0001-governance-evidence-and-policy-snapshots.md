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
- Bootstrap direct-create paths are a named bootstrap exception. Non-bootstrap
  applications require evidence commitments once the evidence feature lands.

## Consequences

Historical evidence can explain both who approved a decision and which policy
they applied. The Compact contract needs policy-version and evidence-verifier
references in addition to the existing threshold and signer-set commitment.
Existing ordinal lifecycle deployments require migration or redeployment before
adding new serialized fields or statuses.

## Rejected Alternatives

- Preserve signer order as policy meaning: rejected because approval order is
  not a governance property and complicates reproducibility.
- Parse VC/VP formats in Compact: rejected because it increases circuit cost,
  binds the contract to evolving encodings, and risks private-data leakage.
- Let an evidence verifier activate an applicant directly: rejected because it
  bypasses registry governance.
