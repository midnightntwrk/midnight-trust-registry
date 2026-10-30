# ADR-0004: Composite Verifier And Auditor Request Identity

Status: proposed for the unreleased 0.1.0 profile

Date: 2026-10-08

## Context

ADR-0002 commits the entire verifier or auditor request scope, but the current
governed resource is the bare `requestProfileId`. Two requests for the same
profile can therefore have different purposes, credential-scope commitments,
attributes, predicates, or disclosure levels while sharing an intake resource
ID. The Compact scope key includes only the profile, allowed-attribute set,
allowed-predicate set, and disclosure-level commitments. It omits purpose and
credential scope, so on-ledger authorizations can also collide.

## Decision

One authorization governs exactly one complete, validated `tr-scope-v1`
verifier or auditor request scope. The role is part of the scope commitment;
verifier and auditor resources cannot be substituted for one another. Every
field in the request scope participates in the resource identity, including
the profile ID, purpose, credential-scope commitment, both sorted and
duplicate-free allowed lists, and disclosure level.

For canonical request scope `S`, define:

```text
C = computeAuthorizationScopeCommitment(S)  // lowercase 0x-prefixed SHA-256
P = JSON.stringify(["tr:request-resource:v1", C])
resourceId = "tr:request-resource:v1:" + lowercaseHex(SHA-256(UTF-8(P)))
resourceIdCommitment = SHA-256(UTF-8(resourceId))
```

For the verifier request vector in ADR-0002, the resource ID is
`tr:request-resource:v1:f86e27170e169eae8c8e185911ea0b56b556e9da9c27bfcb202cb68e49fff6e5`
and the 32-byte Compact commitment is
`0xd960e89a62d3f51b12bcd906261dc3df026badb50f8650e7314746c2d2309823`.
Changing only its role to `auditor` gives resource ID
`tr:request-resource:v1:31c2d80f368b0e66c767a5cd86862e51048a2caddc2b423a6d2d2700d0c90a7e`
and Compact commitment
`0xeafc1934d592b84b1575c273bcb2f00c0cad015bd976da337fa984e2a35bf741`.

The scoped `resourceId` is the `requestProfile` governed-resource ID in the
challenge binding, signed application envelope, authorization record, current
and historical API query, and evidence bundle. The human-readable
`requestProfileId` remains a separate field in the authenticated scope. It is
not itself an authorization key. The contract receives the opaque
`resourceIdCommitment` and commits it in both verifier and auditor records and
scope keys. Its fields and circuit parameters must be named for the resource
commitment, not mislabeled as the bare profile commitment. The contract does
not parse scope JSON; authenticated intake derives and attests the binding.
The existing allowed-attribute, allowed-predicate, and disclosure commitments
remain separate ledger fields, but the full-scope resource commitment is the
non-colliding key component. A raw contract caller can still submit opaque
bytes; without matching authenticated scope evidence, those bytes do not
establish a canonical 0.1.0 verifier or auditor grant.

Challenge issuance MUST validate the canonical scope and recompute the ID
before reserving a nonce. The signed evidence envelope MUST recompute the ID
from its signed scope commitment and role. Records and lookup inputs MUST
reject bare profile IDs. A shaped ID alone does not authenticate a scope
preimage: relying parties MUST obtain authenticated scope evidence and
recompute the ID before interpreting an authorization as a request grant.

No compatibility alias is provided. The repository has no release or live
registry requiring migration; deployments from development snapshots must be
redeployed or explicitly migrated outside this profile.

## Validation

- Same subject and profile with different purposes yield distinct IDs and
  coexist in the verifier ledger and current/historical lookup.
- Same subject and profile with different credential-scope commitments yield
  distinct IDs and coexist in the auditor ledger.
- Changing either allowed list or disclosure level changes the ID; list
  reordering does not change it, and duplicate IDs fail validation.
- Cross-role or cross-scope signed evidence is rejected before nonce consume;
  a consumed nonce never becomes reusable after downstream failure.
- API, simulator, Compact, and independent vector tests agree on the byte
  commitment passed to the contract. Run `./run.sh --light` and full simulator
  integration before publication.

## Rejected Alternatives

- Bare request-profile ID: collides for distinct request policies.
- Adding only purpose to the existing Compact key: still omits credential
  scope and risks future omissions.
- Hashing ad hoc concatenated request fields in Compact: duplicates the
  canonicalization protocol and complicates proof circuits.
