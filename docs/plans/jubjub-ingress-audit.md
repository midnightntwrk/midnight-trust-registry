# JubJub Signature Ingress Audit

Issue: [#101](https://github.com/midnightntwrk/midnight-trust-registry/issues/101).

This is the 0.1.0 local audit map, not a claim that every planned admission
surface is public. The registry currently consumes DID 0.7.0's JubJub package
and VC 0.2.0's DID-aware verifier surfaces.

| Surface | Untrusted input and current check | Remaining proof |
| --- | --- | --- |
| Contract signing helper | `decodeCanonicalJubjubSignatureHex` enforces lowercase fixed-length hex, field and scalar bounds, a valid curve point, and a non-identity announcement. Structured verifiers also reject identity public keys. | Independently establish subgroup semantics across the DID package and Compact circuit. |
| Free client epoch verifier | Parses bundle signature through the canonical decoder and verifies the policy-bound digest against a caller-authenticated key, epoch record, and registry commitment. | Test all malformed wire classes and wrong-key references at this boundary; the caller still owns anchor provenance. |
| Simulator client | Reads the epoch and maintainer key from a format-one simulator ledger and compares bundle registry identity with the ledger commitment. | Test key rotation and historical key status against independently accepted ledger state; the simulator is not a production trust source. |
| Local application-evidence harness | Domain validation selects an allowed key ID; the adapter decodes the wire signature and checks a DID fixture public key while catching runtime faults. | Replace the single-key adapter with governed evidence-verifier selection in #67; test malformed input for each applicant role. |
| Compact governance actions | Typed JubJub fields enter circuits, which reject identity signer keys/announcements, compare the maintainer key ID/public key to an active ledger record, and verify Schnorr under the active policy-bound quorum. There is no hex decoder in-circuit. | Check high-response, malformed-point, and subgroup behavior at the typed client/circuit boundary. |
| API challenge intake | Issues and consumes bound nonce hashes; it does not currently authorize a DID key or verify a JubJub signature. | Do not expose a production admission route until #67 and the VP adapter trust boundary are complete. |
| CLI and TRQP projections | Transport and display registry evidence; neither is a cryptographic signature-admission boundary. | Ensure consumers invoke the anchored client verifier before treating projection output as authorization. |

The two-key DID resolver fixture proves assertion-key selection and a rotated
snapshot, but does not prove that a registry policy authorized either key.
That on-ledger lifecycle and proposal-time binding belong to #67. Do not close
#101 until every actual untrusted signature path has deterministic negative
tests and the Compact versus preflight checks have been independently reviewed.

The point `(0, 1)` is the JubJub identity. Without an explicit rejection, an
attacker could choose a signature announcement equal to a scalar multiple of
the generator and satisfy the Schnorr equation under that public key. The
TypeScript preflight and Compact signer paths now reject this point. This is
not a proof that arbitrary accepted points have prime-order subgroup membership.
