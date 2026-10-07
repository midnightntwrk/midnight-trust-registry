# Issuer Status Policy Binding V1

Status: canonical off-ledger preimage and fixed vector; **not yet a governed
ledger anchor or supported VC status decision**. Tracks #90 and #76.

An issuer authorization that permits credential issuance needs an accepted
status registry and authority. Neither the current evidence bundle's
`referencedStatusRegistryId` nor its status-policy URI is in the signed issuer
authorization leaf. A relying party MUST NOT treat those hints as governance
evidence or let a federation publisher signature authenticate them by proxy.

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

This digest is meaningful only after a governed issuer transition signs and
stores it, historical evidence includes it in the authenticated leaf, and a
client verifies the supplied preimage against that leaf. A verifier must also
resolve the accepted status-authority method at the relevant decision state
and validate the status proof, freshness, and non-revocation against an
authenticated status-registry state. The current VC status-registry package
documents prototype authority and root-verification limitations, so this
encoder alone does not enable a supported status claim or restore federation
status metadata.
