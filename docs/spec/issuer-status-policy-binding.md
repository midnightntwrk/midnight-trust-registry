# Issuer Status Policy Binding V1

Status: governed issuer-authorization commitment and authenticated evidence
preimage, plus a reference DID-signed status-attestation verifier;
**not yet a network-backed VC non-revocation decision**. Tracks #90 and #76.

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
The reference application-VP adapter accepts a signed status assertion only
when the caller supplies this binding from an already verified governed issuer
authorization. The signed statement binds the status registry, assertion
method, status handle, credential body root, application challenge hash,
active flag, and a maximum five-minute observation window. The verifier
resolves the authority's current Midnight DID assertion key, checks its
verification-method reference against the credential status binding, and
verifies the domain-separated JubJub signature. A revoked, stale, substituted,
or unsigned assertion fails closed. This is an authority attestation, not an
independently verified non-revocation proof. The deterministic reference
fetcher does not authenticate a live status-registry root or network finality;
production non-revocation federation claims remain unsupported until that
boundary is implemented. The experimental OpenID Federation authorization
statement may carry this exact binding, its authorization-leaf commitment,
and the TR evidence bundle as a publisher claim. It must discard the old
unanchored hints and reject a substituted binding before signing. A relying
party must still validate the bundled authorization against an independently
accepted epoch and current grant; the federation signature does not supply
that trust anchor or prove live credential status.

`createGovernedApplicationIssuerEligibility` is the reference connection from
current decision evidence to VP intake. The deployment supplies a fixed issuer
selection, permitted application roles, an evidence loader, and trusted readers
that authenticate current finalized registry and DID state. The adapter
requires the presented issuer DID, assertion method and JubJub key, and VC
status-registry ID to match the verified active issuer candidate. It returns
that candidate's governed binding to the VP verifier, which passes it to
`createAttestedApplicationStatusSource` with the exact application challenge
and evaluation instant. A historical or inactive grant cannot authorize new
intake. Fixture-only issuer decisions are not a substitute for trusted readers.
