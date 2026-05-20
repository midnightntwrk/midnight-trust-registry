# Trust Registry Architecture Boundaries

## Boundary Principle

The trust registry owns trust decisions and evidence. It does not own identifiers, credentials, or revocation state.

## Repository Responsibilities

| Repository | Owns | Does not own |
| --- | --- | --- |
| `midnight-did` | DID lifecycle, DID documents, resolver, manager, key operations, DID API | Credential issuance, presentation policy, trust-registry governance |
| `midnight-verifiable-credentials` | VC/VP model, claims, credential families, status/revocation, holder binding, BDD flows | Registry governance, participant onboarding, authority recognition |
| `midnight-trust-registry` | Governance policy, authorization, recognition, historical evidence, query/evidence API | DID CRUD, VC issuing, holder data, revocation accumulators |

## Integration Flow

1. DID creates and resolves party DIDs.
2. TR authorizes a DID for a scoped issuer or verifier role.
3. VC issues or verifies credentials using the DID and TR evidence.
4. Status/revocation checks use VC status registry evidence.
5. Verifiers combine VC proof, status evidence, and TR authorization evidence.

## Why Status Is Not Duplicated

Revocation and status are high-churn operational data. Governance and authorization are slower-moving policy data. Mixing them makes the contract harder to operate, harder to audit, and more expensive to update. The trust registry can require a status method and can record which status registry is accepted for a resource, but it should not become the status registry.

## Authorization vs Recognition

Authorization is a local registry statement: this subject DID can perform this role for this resource.

Recognition is a scoped acceptance statement: this external authority or registry is trusted for this domain under this policy.

The two statement types must remain separate because recognition should not silently grant local write privileges.

## Historical Verification

A verifier may need to validate a credential years after issuance. The registry therefore has to retain enough history to answer what was authorized at a past point in time. Current-state-only lookup is not enough.
