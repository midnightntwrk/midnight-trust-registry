# Evidence-verifier ledger binding for issue #67

Status: local issuer-pilot implementation in progress. Maintainer, verifier,
and auditor proposals remain out of scope until their existing circuits are
migrated without bypasses.

## Current boundary

`applicationEvidenceSignatureDigest` binds a key reference and canonical
envelope commitment for off-ledger intake. The issuer pilot additionally
looks up a governed verifier key and verifies a distinct proposal-bound
signature. The other proposal circuits still accept an opaque evidence hash
after a maintainer quorum action. Off-ledger DID resolution and VP checks do
not by themselves turn that hash into an on-ledger attestation. A second,
optional issuer proposal circuit would leave an unsigned bypass, so the pilot
replaces the existing issuer entry point rather than adding one.

## Issuer pilot invariant

Replace the existing issuer proposal entry point in one coordinated change.
It MUST require an active, quorum-authorized evidence-verifier key and verify
its JubJub signature inside the same transaction that records the proposal.
The signed preimage MUST bind the registry ID, issuer authorization ID, subject
DID commitment, resource type and full canonical resource ID, policy
commitment/version, verifier authorization ID/key reference, and canonical
envelope commitment. The maintainer action payload MUST also bind the verifier
key and evidence commitment. No legacy hash-only proposal circuit or optional
signature flag may remain. This changes the unreleased format in place; do not
add a compatibility/deprecation path.

The application-evidence sidecar, keyed by issuer authorization ID, retains
the verifier authorization ID, DID/key commitments, suite, policy snapshot,
envelope commitment, and governance event reference. The ordinary lifecycle
record retains its existing evidence hash and event chain. Signature verification
must not accept a valid commitment for another issuer, role, resource, policy,
or registry. A verifier key revoked or suspended before proposal must fail;
historical proposals retain the key/policy snapshot used at proposal time.
Approval and activation of a pending issuer proposal also require that its
recorded verifier key remains active and current under the same governance
policy commitment/version. Suspension, revocation, rotation, or policy revision
invalidates the pending transition; archive and reapply under current evidence
instead of silently grandfathering it. The local simulator separately checks
expiry against an independently advanceable evidence clock. Compact cannot
prove wall-clock expiry, so production admission must enforce that off-ledger
precondition before submitting approval or activation.

## Verifier-key lifecycle

Add a ledger record keyed by an immutable authorization ID with DID commitment,
assertion key ID commitment, JubJub public key, suite, active policy
commitment/version, status, governance sequences, predecessor ID for rotation,
and last event hash. A DID/policy scope index identifies the current record;
a separate key-reference index prevents reusing one key reference for a
different DID or public key. Registration requires current policy and maintainer
quorum. Suspension and revocation use the emergency threshold. Rotation
atomically retires the old active record and installs a fresh ID/key while
preserving historical evidence. No self-registration or overwrite of old key
material is allowed. Each action has a domain-separated payload and event hash.

The contract proves that a maintainer quorum authorized a DID/key assertion;
it does not prove that the key appears in the DID method's current document.
DID resolution, assertion-purpose checks, VC/VP verification, challenge
uniqueness, and wall-clock expiry remain off-ledger intake obligations until
separately anchored or proven. Compact epoch sequences are not a wall clock.
The specification's `verifiedAt`/`expiresAt` rejection requirement therefore
needs a precise on-ledger sequence or attested-time rule before claiming that
part of issue #67 complete.

## Migration and tests

1. Add ledger record, scope/key uniqueness indexes, lifecycle circuits, and
   query with quorum, status, duplicate, wrong-policy, and rotation tests.
2. Replace the current issuer proposal circuit and the unreleased signing
   digest together. Migrate TypeScript signing, simulator client, local harness,
   and every direct issuer-proposal fixture in the same branch; do not ship an
   intermediate permissive circuit.
3. Add adversarial cases for wrong key, noncanonical signature, inactive key,
   stale policy/version, altered registry/subject/resource/evidence, replay,
   and replacement with a live issuer scope. Assert sidecar/event snapshots.
4. Run Compact light compile, contract tests, `./run.sh --light`, audit, and
   full local-simulator integration from a fresh full Compact build. Require
   independent final-head security review and protected-branch checks.

This pilot is a partial #67 delivery. Remaining roles and proof of DID-document
key control require separately reviewable slices before closing the issue.
