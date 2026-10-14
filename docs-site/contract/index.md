# Compact contract reference

The contract source is [`contracts/trust-registry/src/trust-registry.compact`](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/contracts/trust-registry/src/trust-registry.compact). This page maps its responsibilities; the source and tests are authoritative for exact circuit parameters.

## Ledger state

| Group | Representative ledger fields | Why it exists |
| --- | --- | --- |
| Registry and policy | `registryId`, `registryDidCommitment`, `governancePolicyCommitment`, version maps, thresholds | Bind a decision to one registry and immutable policy version |
| Maintainers | key IDs, membership records, current-by-DID/key maps, active count | Enforce live distinct quorum and membership safety |
| Role grants | issuer, verifier, auditor ID sets/maps and current scope indexes | Keep exact-scope lifecycle records and prevent duplicate current grants |
| Evidence keys | evidence-verifier and VC authority key records | Admit only governed signatures; support rotation/status history |
| Recognition | recognition records and current scope index | Separate external acceptance from local authorization |
| Events | action count, last event hash, signer-set/payload/policy commitments | Append governed change evidence and prevent stale replay |
| Epochs | commitment records and latest epoch ID | Publish bounded views for query evidence |

Raw credentials, presentations, holder identifiers, and private claims do not belong in this state.

## Circuit families

- `initializeRegistry` performs the one-time bootstrap and records policy/maintainer commitments.
- `propose*`, `authorize*`, `activate*`, `suspend*`, `revoke*`, and `archive*` circuits implement role-specific lifecycle boundaries. Issuer, verifier, auditor, maintainer, and recognition records remain distinct.
- `updateMaintainerThresholdPolicy`, evidence-verifier key governance, and VC authority key governance have separate controlled transitions.
- `policyBoundActionPayloadHash`, `policyBoundMaintainerActionDigest`, and Schnorr verification bind signatures to current policy/action/sequence; quorum is checked inside Compact.
- `get*` and `assert*Authorized` expose records and eligibility assertions to contract-side consumers.
- Epoch circuits commit roots/sequence; they do not create an intrinsic clock or prove network finality by themselves.

## Signature boundary

Contract-facing governance uses JubJub Schnorr keys associated with Midnight DIDs. The API's prepare result is only a signing preimage; Compact independently verifies the supplied signatures, registered keys, membership status, and threshold. A hash or an off-chain `isTrusted` callback is not authorization. External DID methods and Ed25519/secp256k1/P-256 proof suites require an explicit future adapter and governance rule; they are not native Compact verification paths here.

## Test strategy

Pure digest/canonicalization tests cover cross-surface parity and negative substitutions. Simulator integration exercises transitions, stale policy, duplicate signer, missing quorum, replay, and scoped query behavior. `./run.sh --light` is the fast local gate; `pnpm run integration` is broader. These tests validate the reference simulator, not a production network deployment.
