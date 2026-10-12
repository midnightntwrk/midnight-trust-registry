# Trust Registry Documentation

This documentation set is the source of truth for the initial `midnight-trust-registry` implementation.

The [0.1.0 reference profile](spec/milestone-0.1.0.md) defines the next
release gate. The general specification below describes the longer-term v1
system; the [0.1.0 issue plan](plans/milestone-0.1.0-issues.md) names the
remaining implementation and test work.

## Reading Order

1. [0.1.0 reference profile and actor use cases](spec/milestone-0.1.0.md)
2. [0.1.0 executable issue plan](plans/milestone-0.1.0-issues.md)
3. [Trust Registry general specification](spec/trust-registry.md)
4. [Application evidence protocol](spec/application-evidence.md)
5. [Issuer status-policy binding draft](spec/issuer-status-policy-binding.md)
6. [Architecture boundaries](architecture/trust-registry-boundaries.md)
7. [Implementation plan](plans/trust-registry-implementation-plan.md)
8. [Execution backlog](plans/trust-registry-backlog.md)
9. [Research requirements memo](research/trust-registry-requirements-memo.md)
10. [Decisions and open questions](decisions/trust-registry-decisions.md)
11. [ADR-0001: governance evidence and policy snapshots](decisions/adr-0001-governance-evidence-and-policy-snapshots.md)
12. [ADR-0002: resource and request-profile canonicalization](decisions/adr-0002-resource-and-request-profile-canonicalization.md)
13. [ADR-0003: composite issuer resource identity](decisions/adr-0003-composite-issuer-resource-identity.md)
14. [ADR-0004: composite verifier and auditor request identity](decisions/adr-0004-composite-request-scope-identity.md)
15. [ADR-0005: DID-signed mutation intents](decisions/adr-0005-did-signed-mutation-intents.md)
16. [Repo-local knowledge base](decisions/trust-registry-knowledge-base.md)

## Repository Boundary

The trust registry should stay focused on trust policy and registry governance:

- Use `midnight-did` for DID lifecycle, DID document normalization, resolver behavior, and party key management.
- Use `midnight-verifiable-credentials` for VC/VP data model, credential families, status/revocation, holder binding, and presentation protocols.
- Use this repository for registry membership, authorization, recognition, governance policy, historical evidence, and query surfaces.

## Public Documentation Hygiene

Do not commit private notes, local file paths, unpublished credentials, local wallets, or proof-server logs. If research is derived from local notes, turn it into public, source-neutral requirements before committing it.
