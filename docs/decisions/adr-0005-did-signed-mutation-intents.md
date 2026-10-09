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
0.1.0 signer profile uses a `did:midnight` actor. Other DID methods require a
separate verified key-resolution profile, not a permissive fallback.

`submit` is an applicant action for a membership target. Lifecycle and epoch
actions require a maintainer; only `publish-epoch` may target an epoch.
Submitting a maintainer application does not self-enroll the applicant: the
governed approval and activation still require authorized maintainers.

The workspace commitment is the optimistic concurrency token for the *entire*
operator workspace, including the operation log; an epoch ID alone is not
sufficient because multiple writes can occur within one epoch. The API must
publish the commitment computed from a canonical workspace serialization,
check it inside the atomic write boundary, and reject stale intents. The
payload commitment must be independently recomputed from the exact validated
request body; fields may not be defaulted or changed after that check. Nonces
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
