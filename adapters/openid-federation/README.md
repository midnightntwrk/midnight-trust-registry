# Trust Registry OpenID Federation Adapter

Experimental OpenID Federation helpers for `midnight-trust-registry`.

Current scope:

- signed federation entity configuration payloads for the registry
- signed subordinate statements from a fixture trust anchor to the registry
- simple trust-chain verification over fixture-signed entity statements
- explicit custom metadata that embeds canonical TR evidence bundles inside
  registry publication metadata

Out of scope in this slice:

- native OIDC provider or RP metadata projection
- wallet metadata profiles
- live fetch, list, resolve, or `.well-known` federation endpoints
- network fetch or resolve endpoints
