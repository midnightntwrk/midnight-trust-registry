# Trust Registry Client

TypeScript client helpers for querying and validating trust-registry state.

Current scope:

- raw current and historical queries against the local simulator/contract surface
- evidence-bundle verification for issuer, verifier, and recognition decisions
- epoch-anchor verification against published roots and maintainer signatures

This package is the consumer-facing layer on top of the Compact contract. DID-
and VC-backed end-to-end integration remains a later slice.
