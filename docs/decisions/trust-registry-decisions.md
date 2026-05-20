# Trust Registry Decisions

Date: 2026-05-20

## Current Decisions

- Use Midnight DID by default for party and registry identifiers.
- Use Midnight VC and VP packages as the default application evidence surface.
- Keep Schnorr signatures over JubJub-compatible registry control keys as the default contract-facing authorization primitive for v1.
- Admit non-Midnight DID methods only through explicit governance policy.
- Treat secp256k1, secp256r1, and Ed25519 as planned extension paths, not mandatory v1 contract features.
- Treat authorization and recognition as separate statement types.
- Preserve historical state instead of overwriting it.
- Keep this repository as the owner of trust-registry governance and implementation.
- Target long-term package placement under contract, package, adapter, and example directories once source work begins.
- Treat `midnight-did` as a downstream consumer and integration point, not the owner of the registry contract.
- Reuse the VC status registry for status and revocation instead of cloning those concerns.
- For the first issuer-authorization slice, maintainer-approved create lands directly in `active` state; the separate application/proposal workflow remains a later slice.
- Keep the issuer authorization lookup split between a primary `authorizationId` record and a current-scope index keyed by `(subject DID commitment, resource type, resource id)`.
- For the first verifier-authorization slice, keep the authorization lookup split between a primary `authorizationId` record and a current-scope index keyed by `(subject DID commitment, request profile id, allowed attribute set commitment, allowed predicate set commitment, disclosure level commitment)`.
- For the first recognition slice, maintainer-approved create lands directly in `active` state, but recognition remains a separate record family from local authorization.
- Keep the recognition lookup split between a primary `recognitionId` record and a current-scope index keyed by `(recognized authority DID commitment, recognized registry id, scope resource type, scope resource id)`.
- Store recognition scope resource type as an opaque `Bytes<32>` label in the contract so external trust domains are not forced into the issuer/verifier resource enums.
- Start integration coverage with a simulator-first workspace package and a dedicated `./run.sh integration` lane; keep it separate from `./run.sh --light` until DID- and VC-backed scenarios justify the extra CI cost.

## Pending Decisions

- Resource granularity for issuer authorization: credential family, schema version, credential definition, or a combination.
- Whether verifier authorization should later grow beyond the current v1 scope of request profile plus disclosure and predicate commitments.
- Minimum maintainer threshold for admin onboarding, member onboarding, policy updates, and emergency suspension.
- Minimum archival retention window for long-term credential verification.
- First operator-facing app surface: admin CLI, admin console, applicant portal, or public query API.
- First external adapter: TRQP, OpenID Federation, or both.
- When to introduce the separate on-chain application state machine for issuer, verifier, and admin onboarding flows.
