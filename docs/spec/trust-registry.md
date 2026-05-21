# Trust Registry Specification

Status: draft v0.1
Target branch: `develop`
Owner repository: `midnight-trust-registry`

## 1. Purpose

A Midnight trust registry is a governance and policy system that lets applications answer four questions without contacting an issuer at presentation time:

1. Is this issuer authorized for this credential family, schema, or credential definition?
2. Is this verifier authorized to request this presentation profile or disclosure class?
3. Which governance policy, evidence, and historical state made that decision valid at the time of issuance or verification?
4. Which external authorities or registries are recognized, and for what scope?

The registry is not a DID resolver and not a VC issuer. It consumes DID and VC surfaces from the sibling repositories and publishes trust evidence that wallets, issuers, verifiers, and auditors can verify.

## 2. Non Goals

The v1 registry does not:

- Store holder personal data.
- Resolve DID documents itself.
- Issue credentials or presentations.
- Replace VC status or revocation registries.
- Implement every key family on-chain.
- Require an issuer callback during presentation verification.

## 3. Actors

| Actor | Responsibility |
| --- | --- |
| Root governor | Bootstraps registries, policy templates, and maintainer quorum rules. |
| Registry maintainer | Applies governance-approved changes and signs epoch commitments. |
| Authority | External or internal organization that can be recognized for a scoped policy domain. |
| Issuer | DID-identified party authorized to issue credentials for scoped resources. |
| Verifier | DID-identified party authorized to request presentations under scoped request profiles. |
| Holder | Presents credentials. The registry must not track holder activity. |
| Auditor | Verifies historical decisions, evidence bundles, and governance compliance. |

## 4. Identifier Rules

- Midnight DID is the default identifier surface for registries, maintainers, issuers, and verifiers.
- Non-Midnight DID methods are allowed only when a governance policy explicitly admits them.
- Schnorr signatures over JubJub-compatible registry control keys are the default contract-facing authorization primitive for v1.
- secp256k1, secp256r1, and Ed25519 are extension paths. They can be represented in policy and off-chain evidence before native on-chain verification exists.

## 5. Core Resources

### Registry

A registry record defines the governing trust domain.

Required fields:

- `registryId`
- `registryDid`
- `name`
- `description`
- `controllerDids`
- `maintainerDids`
- `policyUri`
- `serviceEndpoint`
- `logoUri`
- `status`
- `createdAt`
- `updatedAt`
- `suspendedAt`
- `revokedAt`
- `supersededAt`
- `archivedAt`
- `lifecycleEventRoot`

### Governance Policy

A governance policy describes who may change the registry and under which process.

Required fields:

- `policyId`
- `registryId`
- `version`
- `policyUri`
- `status`
- `effectiveFrom`
- `effectiveUntil`
- `decisionRules`
- `disputeRules`
- `retentionRules`
- `emergencyRules`
- `supersededAt`
- `archivedAt`
- `lifecycleEventRoot`

### Participant

A participant is a DID-identified issuer, verifier, maintainer, or authority.

Required fields:

- `participantId`
- `participantDid`
- `participantType`
- `legalName`
- `serviceEndpoint`
- `currentKeyRefs`
- `historicalKeyRefs`
- `metadataUri`
- `status`
- `effectiveFrom`
- `effectiveUntil`
- `suspendedAt`
- `revokedAt`
- `supersededAt`
- `archivedAt`
- `lifecycleEventRoot`

### Authorization

An authorization grants a participant a scoped right inside one registry.

Required fields:

- `authorizationId`
- `registryId`
- `subjectDid`
- `role`
- `resourceType`
- `resourceId`
- `policyId`
- `trustLevel`
- `status`
- `proposedAt`
- `authorizedAt`
- `activeFrom`
- `issuedAt`
- `suspendedAt`
- `revokedAt`
- `supersededAt`
- `archivedAt`
- `evidenceHash`
- `lifecycleEventRoot`

`trustLevel` is policy-defined in v1. The registry record stores the value selected by the governing policy, and the evidence bundle must include the policy version that defines the scale. A later schema pass should decide whether common scales become enums or remain policy-local strings.

### Recognition

Recognition records that a registry accepts an external authority or registry for a scoped domain. Recognition is not the same as local authorization.

Required fields:

- `recognitionId`
- `registryId`
- `recognizedAuthorityDid`
- `recognizedRegistryId`
- `scope`
- `policyId`
- `trustLevel`
- `effectiveFrom`
- `effectiveUntil`
- `evidenceHash`
- `status`
- `proposedAt`
- `authorizedAt`
- `suspendedAt`
- `revokedAt`
- `supersededAt`
- `archivedAt`
- `lifecycleEventRoot`

### Resource Authorization

Resource authorization binds issuers and verifiers to VC resources.

Issuer-scoped resources:

- Credential family
- Schema
- Schema version
- Credential definition
- Status method requirement

Verifier-scoped resources:

- Request profile
- Allowed attributes
- Allowed predicates
- Disclosure level
- Presentation purpose

Auditor-scoped resources:

- Audit request profile
- Allowed audit attributes
- Allowed audit predicates
- Disclosure level
- Audit purpose or mandate identifier

### Epoch Commitment

An epoch commitment gives verifiers a stable view of public or permissioned registry state.

Required fields:

- `epochId`
- `registryId`
- `stateRoot`
- `eventRoot`
- `policyRoot`
- `validFrom`
- `validUntil`
- `maintainerSignatures`

## 6. State Model

Registry objects use an explicit lifecycle:

- `proposed`
- `authorized`
- `active`
- `suspended`
- `revoked`
- `superseded`
- `archived`

State transitions must be append-only. Current state can be indexed for fast reads, but prior authorizations, keys, policy versions, revocation timestamps, suspension windows, and archived evidence commitments must remain verifiable.

Every object that carries a lifecycle status must either expose explicit transition timestamps for the known states or expose a `lifecycleEventRoot` that commits to the append-only transition log. Query APIs can return a current-state projection, but evidence bundles must be able to prove the transition history used for a verification decision.

## 7. Contract Surfaces

The expected Compact contract split is:

| Surface | Purpose |
| --- | --- |
| Root governance registry | Creates registries and installs governance policy roots. |
| Participant registry | Tracks maintainers, authorities, issuers, and verifiers. |
| Authorization registry | Tracks role-scoped issuer and verifier authorization. |
| Recognition registry | Tracks recognized external authorities and registries. |
| Epoch anchor | Publishes state roots and maintainer signatures for query/evidence packages. |

Status and revocation stay in the VC status registry. TR records can require a status method, but they do not replace revocation state.

## 8. Query and Evidence Surfaces

The query layer should align with ToIP TRQP concepts while staying implementation-neutral in v1.

The first TRQP-compatible slice should expose standard authorization and recognition queries. Registry metadata and evidence-bundle retrieval should be documented as Midnight profile extensions until TRQP standardizes description or metadata query types.

The first OpenID Federation-compatible slice should authenticate the registry as publisher and carry TR-native evidence bundles inside custom metadata, instead of reinterpreting local authorization state as native OIDC role metadata.

Minimum query answers:

- Registry metadata by `registryId` or `registryDid`.
- Participant metadata by DID.
- Issuer authorization for a credential resource.
- Verifier authorization for a request profile.
- Recognized authority for a scoped domain.
- Historical state at an epoch or timestamp.
- Evidence bundle for a decision.

Minimum evidence bundle fields:

- Subject DID
- Registry ID
- Resource scope
- Policy ID and version
- Authorization or recognition state
- Effective window
- Epoch commitment
- Inclusion proof or signed registry statement
- Relevant maintainer signatures

## 9. DID and VC Integration

DID integration:

- DID creation, update, deactivation, and resolution are delegated to `midnight-did`.
- TR stores DID references and key references, not mutable DID documents as source-of-truth.
- Historical DID/key evidence must be preserved for decisions that outlive key rotation.

VC integration:

- VC packages define credential schemas, credential definitions, holder binding, status, and presentation semantics.
- TR can authorize issuers for VC resource scopes and verifiers for request profiles.
- VC verification can consume TR evidence bundles to decide whether a credential or presentation came from an authorized trust domain.

## 10. Privacy and Security Requirements

- Do not store holder identifiers, holder DIDs, or presentation activity in the registry.
- Do not require issuer callbacks during holder presentation verification.
- Keep high-churn status and revocation writes outside the governance registry.
- Preserve historical state needed for long-term verification.
- Separate authorization from recognition to avoid accidental transitive trust.
- Make public/private access boundaries explicit before introducing permissioned registry data.
- Require governance policy for emergency suspension, key compromise, participant exit, and archival.

## 11. V1 Acceptance Criteria

The v1 implementation is acceptable when:

- A registry can be initialized with maintainers and a governance policy URI.
- Issuer authorization can be created, suspended, revoked, and queried with historical evidence.
- Verifier request-profile authorization can be created, suspended, revoked, and queried.
- Recognition records can be created, revoked, archived, and verified separately from local authorization.
- Epoch commitments can bind the registry state used by a verifier.
- DID and VC integration tests prove that an authorized issuer/verifier path succeeds and a wrong-registry or revoked authorization path fails.
