# Jubjub signature ingress audit (#101)

Status: bounded pre-release audit slice; #101 remains open.

| Boundary | Current check | Remaining trust condition |
| --- | --- | --- |
| Governed Compact action | `verifyAuthorizedMaintainerSigner` matches an active registered key and invokes the DID Schnorr verification circuit over the policy-bound action digest. | A real transaction submission path still needs adversarial witness tests and public error handling. |
| Simulator application evidence | The local harness checks the expected verifier key reference, decodes exact lowercase 96-byte hex, rejects noncanonical scalars/coordinates, and verifies the domain-bound commitment signature. | The key is a simulator fixture. Governed DID key authorization and real VC/VP verification remain #67/#76 work. |
| Client epoch bundle | The client requires exactly one signature for the current single-signer epoch record, accepts only the Jubjub algorithm, decodes exact lowercase 96-byte hex, and verifies it under the supplied maintainer public key and committed publication policy. Bad points fail closed instead of escaping as runtime traps. | The caller must pin the ledger epoch and public key. The bundle's textual DID key reference is not yet authenticated against the ledger byte key ID; #79 must supply that mapping before producing a VC signer descriptor. |
| Simulator epoch assertion | The harness applies the same decoder and algorithm check against its ledger maintainer key. | This is local evidence validation, not an independent network trust anchor. |
| API, CLI, TRQP, federation | They currently consume or project local registry evidence rather than accepting raw Jubjub transaction signatures as a public write gateway. | #77 owns DID-signed mutation intents. #79 owns independent proof verification before adapter publication. |

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
off-curve points, wrong signing keys, and unsupported algorithm labels. #101
remains open for public gateway inventory, multi-key selection and rotation,
and exact key-reference authentication with #67/#79.
The singleton rule is a fail-closed client constraint, not a claim that the
governance quorum consists of one maintainer. Multi-signature epoch provenance
requires a ledger-bound signer set and key-selection rules before the client
can safely accept more than one bundle signature.
