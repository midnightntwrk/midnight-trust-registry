# Trust Registry 0.1.0 Release Candidate

Status: draft, not a release announcement or conformance claim.

The [acceptance evidence map](../plans/milestone-0.1.0-acceptance-map.md)
indexes local tests and the remaining issue-closure work.

## Intended Reference Profile

This candidate targets a self-hosted local Midnight ledger and offline runtime
for a `did:midnight`
applicant. An authorized evidence verifier checks a challenge-bound Midnight
VC/VP fixture off-ledger and signs a redacted application commitment. A
policy-bound quorum of maintainers proposes, approves, and activates an exact
issuer, verifier, auditor, or maintainer grant. An epoch commits the resulting
state, and a relying party verifies current scoped evidence against a finalized
local-ledger readback. Historical authorization and recognition decisions are
out of scope for this candidate and must fail closed rather than use fixture
history.
The applicant portal, admin console, local API, and TRQP projection participate
in the signed actor journeys. Recognition of an external authority remains a
separate, scoped governance decision, not implicit membership.
Kubernetes and Helm are optional installation paths, not acceptance criteria
for this candidate; a non-Kubernetes standalone deployment can qualify with
the same live-ledger, offline-runtime, recovery, and security evidence.

The contract uses JubJub Schnorr signatures for governed actions and commits
registry identity, policy, network, scope, signer, and epoch evidence to
Compact state. The local VC consumer fixture exercises governed issuer and
verifier signer descriptors against a compiled Ledger 8 consumer. It does not
establish synchronous calls between deployed contracts.

## Qualification Evidence Required

Before changing this status to approved, the release owner must record one
signed/DCO source SHA and attach results from that exact tree for:

1. `./run.sh --light`, `./run.sh integration`, and `./run.sh docs`.
2. `pnpm run demo:smoke` and the packed journey for four HTTP membership
   roles plus recognition VC/VP accreditation and governance.
3. `pnpm run packages:check-contents`, `pnpm run artifacts:pack`, and
   `pnpm run artifacts:release-manifest` after a full Compact build.
4. A clean consumer install using the approved manifest with
   `pnpm run packed-artifacts:smoke -- --manifest <path> --actor-journey --vc-consumer`.
5. A real local-ledger deployment with an operator-approved genesis pin,
   independently finalized receipt and readback, and a finalized transition
   from the bootstrap key to an approved threshold-maintenance committee.
6. Online installation from pinned packages and image digests, followed by
   issuer, verifier, auditor, maintainer, and recognition journeys with
   external egress denied for all runtime processes and containers.
7. Independent restart, backup/restore, and ambiguous-outcome recovery checks
   on the same pinned local chain. After each governed mutation, the old
   current-state plan must reject queries until an operator reviews and signs
   a new snapshot/plan set and restarts the API; historical decision routes
   must remain explicitly unavailable.
8. Exact-head CI results, independent security review, release owner sign-off,
   and a recorded recovery/rollback decision. Simulator and mocked-provider
   tests satisfy none of the live local deployment gates above.

The manifest lists artifact bytes and source inputs, plus a sorted
`verifierKeySha256` mapping from every proof-circuit name in generated Compact
metadata to the SHA-256 of its packed `keys/<circuit>.verifier` bytes. Generation
rejects missing, extra, renamed, or source-mismatched keys. Manifest-backed
smoke verifies the complete mapping against the packed contract before
installing packages. A host-invoked deployment adapter now compares the
finalized on-chain verifier-key catalog with this mapping and confirms its
initial single-key maintenance authority at the same checkpoint. This is not
an independent local-ledger readback or approval of that authority model;
the local maintenance transition remains blocking. The manifest alone cannot certify the deployed code.
A matching tarball digest does not by itself prove that every
generated file was built from the recorded
source revision: run the full build and pack on the clean, signed candidate
tree before producing the manifest. The manifest does not authenticate its own
distribution channel or prove any test, review, or network claim.
The preparation job generates and verifies this manifest against the packed
tarball set, runs a clean-consumer smoke, then uploads those bytes and records
the manifest SHA-256 in the workflow summary. Only after that artifact exists
does the `npm-publish` environment gate the publication job. The release owner
must inspect the source, version, manifest digest, and attached artifact before
approving that environment; configure required reviewers in GitHub rather
than assuming the workflow YAML creates them. The protected job downloads the
prepared bytes, checks the reviewed manifest digest, rebuilds full Compact
outputs from the same source, re-verifies the exact manifest and tarballs, and
reruns clean-consumer smoke. It rechecks each selected tarball's manifest-pinned
size and SHA-256 immediately before its `npm publish` call. This catches
accidental or intervening artifact mutation; it does not defend against a
compromised publish runner changing files after that check or substitute for
an accountable release-owner approval.
If a version already exists during a resumed publish job, the job compares
the registry's SHA-512 integrity metadata with the exact manifest-checked
tarball before skipping that immutable version. Missing, weak, or mismatched
integrity stops the job; a non-404 lookup failure is not treated as permission
to publish. A failed or empty package catalog also stops the job instead of
silently succeeding without publishing anything. Offline shell tests cover
these resume and failure paths without contacting a registry. A matching
registry integrity value supports idempotent recovery
from a partial publish, but it does not replace independent approval of the
manifest or authenticate the registry itself.
The release owner must still approve the reviewed manifest and channel.
The private admin-console, applicant-portal, API, CLI, and integration
tarballs are local-only artifacts, not a public npm support promise.

## Trust And Deployment Boundary

Simulator epochs and sequence-to-time mappings are fixtures. Midnight Compact
does not provide a wall clock. A production relying party must independently
authenticate the configured network, deployed contract, finalized ledger and
DID state, historical publication signer context, and time mapping. Neither a
workspace snapshot, HTTP `202`, nor a received evidence bundle is finality.

No independent local-ledger deployment or offline-runtime qualification has
been performed. The deployment and checkpoint adapters are configurable, but they
do not supply a wallet, node-finality proof, or operator approval. The current
local status source is fixture-backed. The VC status-registry package exists
only as a private reference-tier prototype and explicitly requires its
authenticated-authority, accepted-root/non-membership, and trusted-time gates
for supported status profiles; it is not a consumable published dependency or
an approved #90 adapter. The registry never stores raw VCs,
VPs, holder identifiers, or presentation activity.

Preprod is deferred to a later public-network release, with a
governance-aligned threshold maintenance committee. The
[administrator runbook](preprod-admin-qualification.md) is a stop-gated
procedure, not evidence that the deployment or committee transition occurred.
The [standalone offline-runtime plan](standalone-offline-runtime.md) is the
0.1.0 release gate and
requires online installation followed by an egress-denied, self-hosted local
ledger and application journey. It is not satisfied by the simulator fixture
or by future Preprod results. Draft promotion PR #198 stays draft unless its
scope and release gates are explicitly updated and reviewed.

Native non-Midnight DID methods, secp256k1/P-256/Ed25519 verification inside
the Compact contract, transitive federation trust, a distributed API writer,
public-network VC status verification, and synchronous deployed Ledger 8 cross-contract
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
