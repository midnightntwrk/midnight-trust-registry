# ADR-0005: DID-signed mutation intents

Status: accepted for the 0.1.0 reference profile; enforcement is follow-on work in #77.

## Context

The local operator API currently accepts unsigned `{target, label}` submissions
and lifecycle writes. Those routes are demo-only and cannot be exposed as a
governed public API. A server must not substitute its own maintainer signature
for the caller's intent.

## Decision

An applicant or maintainer signs the SHA-256 digest of a fixed-order JSON array
whose first element is `tr:mutation:intent:v1`. The remaining elements, in
order, are registry ID, actor DID, selected actor verification-method ID,
actor role, action, target, target ID,
canonical scope commitment, exact payload commitment, random nonce, expected
workspace commitment, expected epoch ID (or `null`), issued-at, and expires-at.
`MutationIntentSchema` and `computeMutationIntentDigest` are the executable
format. Unknown fields, mixed-case identifiers/commitments, noncanonical UTC
timestamps, and intents lasting longer than five minutes are rejected. The
0.1.0 signer profile uses a four-part `did:midnight` actor with a lowercase
64-hex identifier and a DID-fragment key. The signature signs the raw 32 digest
bytes returned by `mutationIntentDigestBytes`, not the UTF-8 bytes of the `0x`
hex display string. This is narrower than the
DID package's accepted syntax (which can include uppercase on-chain hex and
embedded off-chain state); off-chain DIDs and those alternative spellings are
not accepted as signing identities until a canonical resolver profile prevents aliases. The fragment
itself is case-sensitive and is signed exactly. Other DID methods require a
separate verified key-resolution profile, not a permissive fallback.

Issuer, verifier, and auditor `submit` actions require an applicant. Recognition
proposals require a maintainer. A maintainer proposal may be submitted by the
candidate or an existing maintainer; neither path self-enrolls the candidate.
Governed approval and activation still require authorized maintainers.
Lifecycle and epoch actions require a maintainer; only `publish-epoch` may
target an epoch. For publication, `targetId` is the predecessor epoch ID and
MUST equal `expectedEpochId`; the new epoch ID is determined by the operation.
The preimage reserves the `maintainer` target for UC-03, but the current
operator workspace and HTTP API do not execute it. An adapter MUST reject
unmapped targets rather than treating a valid signed intent as authorization.

The 0.1.0 API preflight verifies the digest bytes with the actor's resolved
Midnight DID JubJub key: applicant submissions require the DID
`authentication` relationship and maintainer actions require
`capabilityInvocation`. The DID signature check alone does not establish
registry maintainer membership or consume a nonce.

The workspace commitment is the optimistic concurrency token for the *entire*
operator workspace, including the operation log; an epoch ID alone is not
sufficient because multiple writes can occur within one epoch. It is SHA-256
over a two-element JSON array containing `tr:workspace:revision:v1` and the
canonical, validated workspace JSON string. `computeOperatorWorkspaceCommitment`
is the executable implementation. The API must publish this token, check it
inside the atomic write boundary, and reject stale intents. It is an off-ledger
revision token, not an independently verified ledger or epoch proof. The payload
commitment uses the same construction with domain `tr:mutation:payload:v1`
and the canonical JSON string of the *validated* governed request body
(`computeMutationPayloadCommitment`). The server MUST independently recompute
this commitment from the exact validated body and compare it before executing;
fields may not be defaulted or changed after that check. A non-JSON value or
explicit undefined field is rejected. The workspace commitment instead
normalizes optional undefined fields to the JSON form persisted on disk.
Nonces
are one-use per registry and actor and remain consumed only after a successful
atomic mutation. API clock checks are off-ledger; Midnight contract circuits
must not infer wall-clock time from these timestamps.

## Consequences

- This ADR and domain helper are a signing preimage only. They do **not** make
  the existing write routes authenticated or production-safe.
- Follow-on #77 slices must define canonical workspace/payload serialization,
  verify a selected policy-authorized DID key and signature, enforce nonce and
  time checks, pass caller signatures into Compact-backed operations, and wire
  both UIs. Until then, the unsigned routes stay loopback/demo-only.
- Future secp256k1, P-256, and Ed25519 DID methods require explicit
  verification adapters and policy authorization; they do not change this
  signed preimage or silently bypass Midnight-native checks.
