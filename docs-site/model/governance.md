# Governance and authorization

Governance answers **who may change trust state and what they must sign**. The first maintainer set is bootstrapped once. Subsequent membership, policy, grants, recognition, and epoch changes are governed actions, not ordinary API writes.

## Quorum

The 0.1.0 reference fixture uses three maintainer DIDs and 2-of-3 for ordinary, membership, emergency, and archival action families. That is a fixture policy, not a universal protocol default. The current Compact signer bundle has five slots, so thresholds above five require a contract change. Signers must be distinct, active, registered, and bound to the exact action and current policy. The candidate cannot count toward its own membership approval, and a change cannot leave fewer active maintainers than the live threshold.

Subject-DID exclusion is enforced for grant approval and activation, for
maintainer removal, and for VC-authority key governance. It is not a blanket
ban on a subject signing a proposal or a negative action on its ordinary grant:
those actions do not increase that subject's trust. Evidence-verifier and grant
deactivation still require the configured maintainer quorum. Consumers must
not interpret the exclusion check as a universal conflict-of-interest policy.

## Signed action transcript

The contract verifies a JubJub Schnorr signature over a domain-separated, policy-bound digest containing action kind, exact payload commitment, sequence, and predecessor event. Policy commitment is included in the signed payload; rotating policy invalidates stale prepared contexts. The contract also checks current membership and quorum rather than trusting a caller-supplied `approved` flag. The [Compact reference](../contract/index.md) maps these checks to ledger fields and circuits.

This simulator transcript does not yet bind the deployment's contract address or
network identity. It must not be reused as a public-network signature format;
cross-deployment replay resistance is a
[0.1.0 release blocker](https://github.com/midnightntwrk/midnight-trust-registry/issues/200).

## Evidence verifier versus maintainer

The evidence verifier checks an applicant's private VC/VP and signs a canonical **redacted** result. A governed active verifier key is required for proposal evidence. Maintainers independently decide whether that exact application is admitted. Neither role substitutes for the other. The VC/VP is not stored in public ledger state.

## Policy rotation

Threshold revision and evidence-verifier registration are two separate actions. The old policy authorizes the revision. The new policy governs the next registration, with a fresh signer set and sequence. Until both succeed, new application evidence must not be treated as authorized under the new policy. A simulator can run both in one demonstration; this is not an atomic network transaction.

The current default maintainer quorum is the meta-governance authority for
`tr:policy:thresholds:update`, including recognition-accreditor anchor
revisions. Emergency and archival thresholds govern their respective actions,
not changes to the policy itself. A public-network policy must specify recovery
and preserve a non-conflicted quorum for maintainer removal: an all-maintainer
emergency or archival threshold can otherwise make removal impossible when the
subject may not vote. This remains a
[0.1.0 release blocker](https://github.com/midnightntwrk/midnight-trust-registry/issues/200).

## Administrative API boundary

`GET /v1/governed/:role/:id/actions/:action` prepares current signer context; `POST` submits externally produced signatures to an injected Compact-backed port. The API does not sign on maintainers' behalf. A stale context is rejected. The packaged CLI has no such port and returns `503` for that route. The unsigned `/v1/applications` and `/v1/epochs/publish` routes are explicitly limited to loopback `--unsafe-demo-mutations` mode.
