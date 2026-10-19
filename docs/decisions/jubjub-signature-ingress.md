# Jubjub signature ingress audit (#101)

Status: bounded pre-release audit slice; #101 remains open.

| Boundary | Current check | Remaining trust condition |
| --- | --- | --- |
| Governed Compact action | `verifyAuthorizedMaintainerSigner` matches an active registered key and invokes the DID Schnorr verification circuit over a deployment-, policy-, action-, and sequence-bound digest. | A real transaction submission path still needs adversarial witness tests, authenticated network selection, and public error handling. |
| API governed proposal and lifecycle votes | Request schemas constrain signer IDs, points, and signature encodings. The shared decoder rejects noncanonical signatures; preflight checks duplicate IDs and deployment-bound vote digests before the configured port submits. | Supplied public keys are not authority by themselves. The port and Compact circuit must check active registered keys, policy, quorum, and exact action context. Public mutation admission remains gated by #77/#167. |
| API DID-signed mutation intents | The configured `/v1/mutations` route parses a strict intent and signature, resolves the selected DID method for the required relationship, checks prime-order key and canonical signature, then rechecks nonce, workspace revision, scope, actor, and operation inside the atomic write boundary. Malformed wire syntax returns 400; a well-formed invalid signature returns a redacted 401 without consuming the nonce. | The resolver must provide authentic DID state. A valid signature does not grant a registry role or make reserved maintainer actions executable; public exposure remains gated by #77/#167. |
| VP evidence attestation | The integration port verifies the evidence signer against its DID assertion method before and after signing, decodes the exact canonical signature, and checks its commitment before one-use intake can propose. | The configured VC/VP and status authority sources must be authenticated and durable; #76/#90 remain release gates. |
| DID authority and status attestations | Recognition authority, recognition status, and application status now require a nonidentity prime-order DID key before canonical Schnorr verification. Malformed signatures and invalid curve points fail as invalid evidence instead of escaping as runtime traps. | An authenticated current or historical DID resolver and the separately pinned authority/status policy are still required. A DID assertion relationship alone is not registry authorization. |
| Simulator application evidence | The local harness checks the expected verifier key reference, decodes exact lowercase 96-byte hex, rejects noncanonical scalars/coordinates, and verifies the domain-bound commitment signature. | The key is a simulator fixture, not independent DID or VC/VP authorization. |
| Client epoch bundle | The client requires exactly one signature for the current single-signer epoch record, accepts only the Jubjub algorithm, binds the textual DID key reference to the epoch record's byte key-ID commitment, decodes exact lowercase 96-byte hex, and verifies it under the supplied maintainer public key and committed publication policy. Bad points fail closed instead of escaping as runtime traps. | The caller must independently pin the ledger epoch and public key and authenticate the DID method/version; comparing to a caller-supplied record alone does not establish trust. |
| Simulator epoch assertion | The harness applies the same decoder and algorithm check against its ledger maintainer key. | This is local evidence validation, not an independent network trust anchor. |
| CLI, TRQP, federation | They consume or project registry evidence rather than acting as an independent public signature-verification gateway. | #79 owns independently pinned proof verification before adapter publication. |

The domain `MaintainerSignatureSchema` permits several planned algorithms, so
the shared record schema does not silently reinterpret all signature strings
as Jubjub. Strict wire decoding belongs at each Jubjub verification boundary.
`decodeCanonicalJubjubSignatureHex` rejects missing prefixes, odd/truncated
lengths, uppercase/non-hex input, out-of-range coordinates, and high response
scalars. Structured TypeScript verification also returns `false` for malformed
or off-curve inputs; only the Compact circuit decides governed on-ledger
actions. Neither TypeScript preflight nor a caller-provided key reference is a
substitute for that circuit or a pinned registry key.

The current negative fixtures cover bad encodings, response malleability,
off-curve points, wrong signing keys, and unsupported algorithm labels. The
configured mutation HTTP boundary additionally verifies redacted 400/401
outcomes and no nonce consumption for malformed or noncanonical signatures;
the one-use VP intake asserts a retired DID method is detected after signing
and before proposal. DID-level two-key fixtures also test exact method
selection and rejection after rotation in mutation-intent and VP evidence ports.
An adversarial fixture confirmed that raw Schnorr verification accepted a
fabricated signature under an identity DID key. The three attestation paths now
share a prime-order guard; identity, nonidentity low-order, off-curve, and
high-response inputs are rejected in focused tests. #101 remains open for
full cross-surface final-head review, policy-authorized multi-key selection in
Compact, and independently authenticated ledger/DID method evidence with
#67/#79. DID-method membership alone is not registry authorization.

The singleton rule is a fail-closed client constraint, not a claim that the
governance quorum consists of one maintainer. Multi-signature epoch provenance
requires a ledger-bound signer set and key-selection rules before the client
can safely accept more than one bundle signature.

The simulator verifier and the published bundle schemas enforce the same
singleton rule for the current format-one epoch record.

The contract may require a quorum of up to five maintainers to authorize the
publish action, but `EpochCommitmentRecord` persists only signer 1's key and
signature. A bundle cannot prove the full publish quorum from that record;
this singleton signature authenticates the anchored epoch, not the quorum
history. Additional ledger-bound provenance is required before expanding the
wire schema or claiming quorum verification from a bundle.
