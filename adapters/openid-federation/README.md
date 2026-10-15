# Trust Registry OpenID Federation Adapter

Experimental OpenID Federation helpers for `midnight-trust-registry`.

Current scope:

- signed federation entity configuration payloads for the registry
- signed subordinate statements from a fixture trust anchor to the registry
- simple trust-chain verification over fixture-signed entity statements
- explicit custom metadata that embeds TR authorization and recognition
  evidence bundles, excluding unauthenticated status hints
- issuer subordinate statements expose the complete governed status-policy
  binding and its authorization-leaf commitment alongside the evidence bundle

Signed federation statements omit the bundle's unauthenticated status-registry
identifier and policy URI. The issuer status claim is accepted only when its
preimage matches the authorization-leaf commitment. This is a consistency
check, not proof of ledger inclusion or finality: relying parties must verify
the embedded TR bundle against an independently accepted epoch before using
the status registry or authority. A federation publisher signature alone
cannot authorize an issuer or prove non-revocation.

Out of scope in this slice:

- native OIDC provider or RP metadata projection
- wallet metadata profiles
- live fetch, list, resolve, or `.well-known` federation endpoints
- network fetch or resolve endpoints
