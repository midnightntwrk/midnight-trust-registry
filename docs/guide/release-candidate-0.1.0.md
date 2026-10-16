# Trust Registry 0.1.0 Release Candidate

Status: draft, not a release announcement or conformance claim.

The [acceptance evidence map](../plans/milestone-0.1.0-acceptance-map.md)
indexes local tests and the remaining issue-closure work.

## Intended Reference Profile

This candidate is a local Midnight simulator reference for a `did:midnight`
applicant. An authorized evidence verifier checks a challenge-bound Midnight
VC/VP fixture off-ledger and signs a redacted application commitment. A
policy-bound quorum of maintainers proposes, approves, and activates an exact
issuer, verifier, auditor, or maintainer grant. An epoch commits the resulting
state, and a relying party verifies current and historical scoped evidence.
The applicant portal, admin console, local API, and TRQP projection participate
in the signed actor journeys. Recognition of an external authority remains a
separate, scoped governance decision, not implicit membership.

The contract uses JubJub Schnorr signatures for governed actions and commits
registry identity, policy, network, scope, signer, and epoch evidence to
Compact state. The local VC consumer fixture exercises governed issuer and
verifier signer descriptors against a compiled Ledger 8 consumer. It does not
establish synchronous calls between deployed contracts.

## Qualification Evidence Required

Before changing this status to approved, the release owner must record one
signed/DCO source SHA and attach results from that exact tree for:

1. `./run.sh --light`, `./run.sh integration`, and `./run.sh docs`.
2. `pnpm run demo:smoke` and the four-role packed actor journey.
3. `pnpm run packages:check-contents`, `pnpm run artifacts:pack`, and
   `pnpm run artifacts:release-manifest` after a full Compact build.
4. A clean consumer install using the approved manifest with
   `pnpm run packed-artifacts:smoke -- --manifest <path> --actor-journey`.
5. Exact-head CI results, independent review, release owner sign-off, and a
   recorded recovery/rollback decision.

The manifest lists artifact bytes and source inputs. It does not authenticate
its own distribution channel or prove any test, review, or network claim.
The private admin-console, applicant-portal, API, CLI, and integration
tarballs are local-only artifacts, not a public npm support promise.

## Trust And Deployment Boundary

Simulator epochs and sequence-to-time mappings are fixtures. Midnight Compact
does not provide a wall clock. A production relying party must independently
authenticate the configured network, deployed contract, finalized ledger and
DID state, historical publication signer context, and time mapping. Neither a
workspace snapshot, HTTP `202`, nor a received evidence bundle is finality.

No funded public deployment or independent network qualification has been
performed. The deployment and checkpoint adapters are configurable, but they
do not supply a wallet, node-finality proof, or operator approval. The current
local status source is fixture-backed; the VC status-registry package is not
yet a consumable published dependency. The registry never stores raw VCs,
VPs, holder identifiers, or presentation activity.

Native non-Midnight DID methods, secp256k1/P-256/Ed25519 verification inside
the Compact contract, transitive federation trust, a distributed API writer,
live VC status verification, and synchronous deployed Ledger 8 cross-contract
consumption are not claimed by this candidate.

## Owner And Recovery Decision

Release owner: **not yet confirmed**. Publication must remain disabled until
an accountable owner approves the manifest, the exact-head evidence, and the
distribution channel. If qualification fails before publication, retain the
failed report and do not publish the candidate. If an immutable package has
already been distributed, do not silently replace bytes at the same version;
publish a separately reviewed corrective version and tell consumers which
manifest and version to reject. Any deployed-registry incident requires a
separate governed response and cannot be repaired by repacking npm artifacts.
The owner must approve the concrete notification and recovery procedure
before the protected publish workflow is used.
