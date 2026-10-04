# Trust Registry OpenID Federation Adapter

Experimental OpenID Federation helpers for `midnight-trust-registry`.

Current scope:

- signed federation entity configuration payloads for the registry
- signed subordinate statements from a fixture trust anchor to the registry
- simple trust-chain verification over fixture-signed entity statements
- explicit custom metadata that embeds TR authorization and recognition
  evidence bundles, excluding unauthenticated status hints

Signed federation statements omit the bundle's unauthenticated status-registry
identifier and policy URI. Federation signing must not promote these hints to
governed status-policy evidence; an anchored status binding is deferred to #76.

Out of scope in this slice:

- native OIDC provider or RP metadata projection
- wallet metadata profiles
- live fetch, list, resolve, or `.well-known` federation endpoints
- network fetch or resolve endpoints
