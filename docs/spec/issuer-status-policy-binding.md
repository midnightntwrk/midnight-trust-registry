# Issuer Status Policy Binding V1

Status: governed issuer-authorization commitment and authenticated evidence
preimage; **not yet a supported VC status decision**. Tracks #90 and #76.

An issuer authorization that permits credential issuance needs an accepted
status registry and authority. The old evidence-bundle
`referencedStatusRegistryId` and status-policy URI are not governance evidence.
The issuer verifier rejects those hints rather than letting a federation
publisher signature authenticate them by proxy.

`IssuerStatusPolicyBindingSchema` is the strict V1 preimage. It binds:

- the trust-registry ID and issuer authorization ID;
- the VC-side 32-byte status-registry ID, not a display label;
- an exact status-authority DID verification-method URL;
- a status-policy ID, monotonic `vN` version, and lowercase 32-byte content
  commitment.

The commitment is SHA-256 of the UTF-8 bytes of
`tr:issuer-status-policy:v1`, one zero byte, and the canonical JSON object.
The JSON object has lexicographically sorted field names and exact validated
strings; unknown fields, noncanonical hex, ambiguous versions, and malformed
DID method references are rejected. The content commitment must cover the
status policy's operative rules and any published URI; a mutable URI alone is
not an authority claim. The reference test fixes the vector
`0x017aa24b5830dd91bb75baf2dc6306316fb45da1f2f79b77d1bbc574589510a8`.

The issuer proposal signs the digest as part of its action payload and stores
it on the ledger. Subsequent lifecycle transitions retain the same digest.
The epoch statement leaf includes it for current and historical evidence.
The issuer bundle carries the preimage; the client first verifies the epoch
and statement leaf, then requires the preimage's registry and authorization
IDs and recomputed digest to match the governed record. Missing, substituted,
or unanchored status metadata fails closed. A changed status policy requires
a new governed issuer authorization rather than silently editing an active
record.

This authenticates the accepted registry and authority *identifier*, not a
credential's live status. A verifier must still resolve the status-authority
DID method at the relevant decision state and validate the status proof,
freshness, and non-revocation against an authenticated status-registry state.
The current VC status-registry package documents prototype authority and
root-verification limitations, so this binding alone does not enable a
supported non-revocation decision or restore a federation status claim.
