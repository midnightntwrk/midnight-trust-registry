# Trust Registry Integration

Integration scenarios for `midnight-trust-registry`.

Current coverage:

- local simulator trust-decision flows for issuer, verifier, and recognition
- anchored epoch evidence validation
- DID-backed resolution of trusted `did:midnight` subjects through official
  `midnight-did` helpers
- VC-backed issuer-descriptor construction using the published
  `@midnight-ntwrk/credential-compact` and
  `@midnight-ntwrk/credential-did-midnight` packages after TR bundle and DID
  method verification, plus registry-bound status-reference hashing. This does
  not prove a live cross-contract trust anchor or revocation state;
  policy-to-VC scope mapping and live status evidence remain separate work.
