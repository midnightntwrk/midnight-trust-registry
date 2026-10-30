# Canonical maintainer bundles in 0.1.0

Issue #206 exposes a production bundle builder that sorts signed authorizers by
the same little-endian bytes32 key-ID order enforced by Compact. The simulator
uses that builder; the transaction submitter is not necessarily the first
canonical signer. The epoch-evidence client rejects duplicate, out-of-order, or
event-hash-mismatched signer sets before Schnorr verification, but still checks
every signature for accepted evidence.
The simulator adversarial matrix labels duplicate-bundle rejections as a
client-side boundary; a separate direct circuit test confirms equal signer
IDs still fail Compact's strict ordering check without advancing state.

The Compact action path already checks adjacent signer IDs with strict `<`
before `finalizeAuthorizedMaintainerAction` calls the internal signer-set hash.
That hash deliberately does not revalidate order. The exported pure
`maintainerSignerSetHash` *does* validate order and zero padding for external
callers. Replacing the internal hash with the exported checked circuit would
duplicate checks in the action path; changing `<` to `<=` would admit duplicate
votes. Neither change is adopted. Hoisting limb decomposition across adjacent
comparisons might save constraints, but requires a separate measured Compact
variant and preservation of distinct duplicate-vote diagnostics.

Reference artifact at Compact source SHA-256
`23c9b9894ded2dca77621ed74b7e239b3f37c5bcd948d57b0408824ae8706a81`:

| `authorizeMaintainerAuditEvent` artifact | Bytes |
| --- | ---: |
| ZKIR | 241,532 |
| binary ZKIR | 19,084 |
| prover key | 169,446,591 |
| verifier key | 2,311 |

The reference package's pure signer-set hash took 27.8 ms for 1,000 warm
calls on the local developer host. This is not a proof-generation benchmark.
This slice changes no Compact source or generated artifact, so it makes no
claim of prover-size or proof-latency improvement. A future Compact change
must compare generated ZKIR, keys, and proof wall time against this pinned
reference before adoption.
