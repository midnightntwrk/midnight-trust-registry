# ADR-0002: Resource And Request-Profile Canonicalization

Status: accepted

Date: 2026-07-27

## Context

Issuer and verifier authorization must produce deterministic answers across the
contract, API, evidence bundle, TRQP adapter, and OpenID Federation metadata.
Free-form resource identifiers cannot safely express schema evolution or
presentation disclosure policy.

## Decision

Issuer scope is an exact canonical object with these required fields:

```json
{
  "credentialFamilyId": "https://schemas.midnight.network/credentials/organization",
  "schemaId": "https://schemas.midnight.network/organization/v1",
  "schemaVersion": "1.0.0",
  "credentialDefinitionId": "did:midnight:credential-definition:organization-v1",
  "statusMethod": "midnight-status-registry-v1"
}
```

Expected scope commitment:

```text
0xddaaffa1002d2beca07f247a32b3feba372e9075753464c0aa230ed083bf61ee
```

Verifier and auditor scope is an exact canonical object with these required
fields:

```json
{
  "requestProfileId": "https://profiles.midnight.network/admissions/v1",
  "purpose": "university-admission",
  "credentialScopeCommitment": "0x...32-byte-hex...",
  "allowedAttributes": ["degree", "issuer"],
  "allowedPredicates": ["age_over_18"],
  "disclosureLevel": "minimum"
}
```

Scope identifiers are `SHA-256` of the RFC 8785 canonical JSON object, encoded
as lowercase `0x`-prefixed 32-byte hex. Arrays are sorted lexicographically
before canonicalization. V1 permits exact match only: no wildcard, implicit
schema-version range, delegation, or transitive external authorization.
External authorization requires a separate recognition record.

The following canonical inputs are required test vectors. Implementations MUST
produce the same scope commitment for the exact JSON object after array
sorting:

```json
{
  "allowedAttributes": ["degree", "issuer"],
  "allowedPredicates": ["age_over_18"],
  "credentialScopeCommitment": "0x1111111111111111111111111111111111111111111111111111111111111111",
  "disclosureLevel": "minimum",
  "purpose": "university-admission",
  "requestProfileId": "https://profiles.midnight.network/admissions/v1"
}
```

## Consequences

Scope evolution produces a new authorization scope. Applications must request
a new authorization when a credential definition, schema version, requested
attribute, predicate, disclosure level, or purpose changes. Adapters project
the canonical identifier but do not create alternate matching semantics.

## Rejected Alternatives

- Free-form resource strings: rejected because scope comparisons become
  implementation dependent.
- Wildcards and version ranges in v1: rejected because their authorization
  semantics are hard to audit and revoke.
- Implicit trust through another registry: rejected because recognition must
  remain separate from local authorization.
