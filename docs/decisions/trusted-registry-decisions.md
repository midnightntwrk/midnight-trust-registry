# Trusted Registry Decisions

Date: 2026-05-20

## Current Decisions

- Use Midnight DID by default for party and registry identifiers.
- Use Midnight VC and VP packages as the default application evidence surface.
- Keep JubJub-compatible registry control keys as the default contract-facing signature primitive for v1.
- Admit non-Midnight DID methods only through explicit governance policy.
- Treat secp256k1, secp256r1, and Ed25519 as planned extension paths, not mandatory v1 contract features.
- Treat authorization and recognition as separate statement types.
- Preserve historical state instead of overwriting it away.
- Keep this repository as the owner of trust-registry governance and implementation.
- Target long-term package placement under contract, package, adapter, and example directories once source work begins.
- Treat `midnight-did` as a downstream consumer and integration point, not the owner of the registry contract.
- Reuse `credentials-status-registry` for status and revocation instead of cloning those concerns.

## Pending Decisions

- Resource granularity for issuer authorization: credential family, schema version, credential definition, or a combination.
- Resource granularity for verifier authorization: request profile only, or request profile plus disclosure and predicate commitments.
- Minimum maintainer threshold for admin onboarding, member onboarding, policy updates, and emergency suspension.
- Minimum archival retention window for long-term credential verification.
- First operator-facing app surface: admin CLI, admin console, applicant portal, or public query API.
- First external adapter: TRQP, OpenID Federation, or both.
