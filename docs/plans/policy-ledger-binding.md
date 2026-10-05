# Policy snapshot ledger binding (issue #75)

Status: local implementation in progress; not yet ready for a PR.

The local branch now binds a canonical V1 snapshot digest to contract version 2
bootstrap and to an atomic, quorum-signed threshold revision. The ledger keeps
versioned historical digests, and epoch publication rejects unknown or
out-of-window policy roots. The simulator selects the digest effective at the authorization's
sequence, including when an old epoch is published after rotation. Client and
simulator verification recompute the policy preimage digest.

Still required before publication: complete the full Compact/integration run,
bind active policy identity to each application and authorization action, and
document the migration boundary for existing contract-version-1 state. The
contract does not parse the off-chain JSON policy preimage; its signatures
attest only to the disclosed digest and threshold tuple.

## Boundary

The V1 domain encoder in `policy-snapshot.ts` defines canonical policy bytes
and their SHA-256 digest. Compact cannot recompute that JSON digest from the
opaque policy record. The contract must instead verify maintainer signatures
over the disclosed digest, version, thresholds, and action sequence, then
commit the digest to ledger state. A consumer must independently recompute the
digest from the policy record before treating the committed value as its
policy. A signature on a digest is not proof that the signers supplied the
correct preimage.

The existing contract-version-1 `governancePolicyCommitment` was only a
commitment to `policyId` in simulator bootstrap and was unchanged by threshold
updates. It must not be relabelled as a V1 snapshot digest for historical
records. The version-2 reference profile is a new deployment; legacy root-only
deployments remain queryable as legacy evidence but cannot satisfy V1 policy
verification without a separately governed migration.

## Contract state and actions

1. Bootstrap discloses the V1 snapshot digest and monotonic policy version,
   binds both to the initialization payload hash, and stores them with the
   initial thresholds. Reject zero digest, noninitial version, duplicate
   initialization, and thresholds exceeding the five-signer ceiling.
2. Policy revision discloses the next digest, version, and ordinary,
   emergency, and archival thresholds. Its signed payload binds all of these
   fields plus the current digest, so a signature cannot be replayed across
   versions or a changed threshold set. Require a strictly increasing version
   and maintain the active-maintainer threshold invariant.
3. Store the active digest and version in ledger state and preserve each
   historical digest by version. Emit a policy-change event hash that includes
   previous and next commitments. Do not mutate past version entries.
4. Application proposals and later governance decisions bind the active
   snapshot digest into their action payloads. Each authorization retains the
   digest effective for its decision; a later revision must not reinterpret
   that decision. The epoch policy root uses the corresponding committed
   digest, not a hash of the policy ID.
5. Maintain separate scope commitments for issuer, verifier, auditor, and
   maintainer authorizations. The contract signs and stores the 32-byte digest
   but does not claim to parse the domain's role-specific JSON preimage.

## Off-chain verification

- The simulator and API derive a snapshot from the policy record and compare
  its digest to the signed ledger value before publishing an epoch or evidence
  bundle. They must reject a mismatched version, policy identity, window, or
  threshold even when a Merkle proof itself is valid.
- The client verifies the source policy record against the committed snapshot
  and evaluates the historical digest and effective window at the decision
  time. TRQP and OpenID Federation may project only this verified view.
- Legacy policy records are explicit migration cases, never implicit V1
  snapshots. A superseding application references its predecessor instead of
  rewriting the previous authorization or policy interpretation.

## Validation sequence

1. Add fixed domain-to-contract byte vectors for the initial three-maintainer,
   2-of-3 profile and for an incremented revision. Assert the same digest in
   the wrapper, ledger, epoch, evidence bundle, and client.
2. Add adversarial tests for wrong digest/preimage, old version reuse,
   same-version reinterpretation, threshold above five or above active
   maintainers, self-vote, duplicate bootstrap, stale epoch, and a historical
   bundle after policy rotation.
3. Wire API, TRQP, and federation only after the contract-facing simulator and
   client tests pass. Run `./run.sh --light` and `./run.sh integration` from a
   pinned Compact toolchain before publishing this slice.
