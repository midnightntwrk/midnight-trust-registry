# VC Signer Authorization Vector Audit

Status: local 0.1.0 candidate evidence, not issue closure or public-network qualification.

The Trust Registry emits a VC signer descriptor only after the selected current
finalized decision and DID method are checked. An issuer descriptor requires an
active grant for the exact `schema` resource. A broader family grant, a
schema-version grant, a definition grant, and a status-method grant are not
implicit schema authority. The VC descriptor's narrower `SchemaRef` scope is
not a credential-definition, status, or live non-revocation decision.

| #79 / #73 vector | Local executable evidence | Boundary |
| --- | --- | --- |
| Active issuer and verifier | `decision-evidence-simulator.integration.test.ts` constructs both candidates and signed authority proofs; `packed-vc-consumer-scenario.mjs` installs both in the Ledger 8 fixture. | Simulator and packed local consumer, not public network. |
| Wrong network or registry | The source integration test substitutes deployment/publication network commitments and the authority domain; the packed fixture rejects a registry-domain substitution. | Finality and genesis still depend on trusted host readers. |
| Unpinned root, stale epoch, tampered inclusion | `decision-context.test.ts` rejects an unavailable or changed accepted root and current sequence; the source integration test rejects changed finalized epoch IDs/roots and grant leaves. | A caller-supplied reader must authenticate the returned checkpoint. |
| Withdrawn schema or suspended party | `vc-scope.test.ts` rejects non-schema issuer grant types; the source integration test suspends the selected schema and verifier grants and rejects new active signing before key custody. | The local grant lifecycle is simulated; consumer revocation delivery is asynchronous. |
| Wrong request profile or signer DID key | The source integration test substitutes verifier resource selection and DID method/key observations; the packed fixture rejects wrong request scope, method, and public key. | DID state must come from an independently finalized reader. |
| Forged signature, replay, DID rollback, revoked-to-active | `packed-vc-consumer-scenario.mjs` rejects forged credential and authority signatures, repeated sequence, DID-version rollback, and revoked-to-active replay. | The fixture compiles from packed artifacts but is not a deployed contract. |

Before closing #79 or #73, run full integration and the packed consumer smoke
at the exact candidate SHA, compare the exported descriptor/proof vectors with
the VC conformance suite, and obtain independent review. #90 still requires a
concrete VC-owned status-authority adapter; #200/#213 still require an approved
maintenance model and funded public-network qualification. Do not infer live
credential status or a synchronous cross-contract read from these tests.
