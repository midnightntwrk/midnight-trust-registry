# Trust Registry Documentation

This documentation set is the source of truth for the initial `midnight-trust-registry` implementation.

## Reading Order

1. [Specification](spec/trust-registry.md)
2. [Architecture boundaries](architecture/trust-registry-boundaries.md)
3. [Implementation plan](plans/trust-registry-implementation-plan.md)
4. [Execution backlog](plans/trust-registry-backlog.md)
5. [Research requirements memo](research/trust-registry-requirements-memo.md)
6. [Decisions and open questions](decisions/trust-registry-decisions.md)
7. [Repo-local knowledge base](decisions/trust-registry-knowledge-base.md)

## Repository Boundary

The trust registry should stay focused on trust policy and registry governance:

- Use `midnight-did` for DID lifecycle, DID document normalization, resolver behavior, and party key management.
- Use `midnight-verifiable-credentials` for VC/VP data model, credential families, status/revocation, holder binding, and presentation protocols.
- Use this repository for registry membership, authorization, recognition, governance policy, historical evidence, and query surfaces.

## Public Documentation Hygiene

Do not commit private notes, local file paths, unpublished credentials, local wallets, or proof-server logs. If research is derived from local notes, turn it into public, source-neutral requirements before committing it.
