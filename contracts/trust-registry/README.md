# Trust Registry Contract

Minimal Compact contract package for the Midnight trust registry.

Current scope:

- registry initialization
- bootstrap maintainer registration
- generic maintainer authorization with fixed-capacity quorum bundles
- maintainer threshold-policy updates for default, emergency, and archival actions
- issuer authorization lifecycle and scope queries
- verifier authorization lifecycle and scope queries
- recognition lifecycle and scope queries
- epoch-anchor publication and current/by-id lookup

The current quorum implementation supports up to `5` maintainer signers per
action bundle so the contract can cover `3-of-5` and `5-of-7` governance
shapes without dynamic arrays. Historical lookup by timestamp, richer
governance policy bindings, and client-facing mutation/query adapters still
stack on top of this package.
