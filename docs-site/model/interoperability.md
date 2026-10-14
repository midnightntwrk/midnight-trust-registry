# Recognition and interoperability

**Recognition is not authorization.** A recognition record says that this local registry accepts a named external authority or registry for an exact scope under a named local policy. It does not enroll that authority as a local issuer, verifier, auditor, or maintainer.

## Evidence path

The reference Midnight profile combines an authority assertion from the authority's DID key with an independently verified accreditation VC/VP. The assertion binds the target registry, recognition ID, authority DID, external registry ID, exact scope, submitted VP commitment, challenge, and bounded validity. It proves key control, not accreditation truth. A locally governed accreditor anchor and credential status check are separate requirements. The evidence verifier signs the redacted combined commitment; maintainers then approve the recognition.

The current simulator uses Midnight DID/VC fixture material. A public production intake would require a governed active anchor and independently validated live status. `did:web` or non-JubJub authority proofs need explicit adapters and trust-anchor rules. See the [recognition plan](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/plans/recognition-accreditation-vp.md).

## Protocol projections

| Surface | Current role | Important limit |
| --- | --- | --- |
| TRQP adapter | Query/metadata and evidence projection | A protocol response is not a substitute for independent epoch verification |
| OpenID Federation adapter | Entity-statement/metadata projection experiment | A trust chain does not automatically create a local grant |
| VC trusted anchor | Produce/verify issuer or verifier decision evidence for VC consumers | Consumer pins registry authority locally; a relayer cannot choose it |

For the native VC anchor, the API's `client-required` decision-evidence response is only a claim. A consumer checks the epoch against an independently finalized Compact ledger view, reads the current issuer/verifier record from that view's exact scope index, and verifies the subject DID at an independently authenticated state. The integration package provides this Compact projection, but the embedding host must still establish network finality, historical publication signer provenance, DID-state provenance, and the evaluation-time mapping. Only then may the consumer accept a pinned-domain VC authority proof. The local governed demo uses simulator state for those host inputs and is not a live-network trust decision.

Interop with another registry requires a mapping of identifiers, scopes, semantics, policy versions, key/algorithm suites, evidence format, revocation/time model, and anchor/finality. If any mapping cannot preserve exact scope and verifiable authority, fail closed rather than importing a `trusted` boolean. Native contract verification remains JubJub in this reference implementation; secp256k1, P-256, and Ed25519 evidence may be evaluated off-chain only under a future explicit adapter and policy.
