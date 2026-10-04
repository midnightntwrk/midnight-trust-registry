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
  "version": "tr-scope-v1",
  "role": "issuer",
  "credentialFamilyId": "https://schemas.midnight.network/credentials/organization",
  "schemaId": "https://schemas.midnight.network/organization/v1",
  "schemaVersion": "1.0.0",
  "credentialDefinitionId": "did:midnight:credential-definition:organization-v1",
  "statusMethod": "midnight-status-registry-v1"
}
```

Expected scope commitment:

```text
0xf9d7d610bba907f28353425136f9ba2bc65d5925421371fc7580716029b3c6c8
```

Verifier and auditor scope is an exact canonical object with these required
fields:

```json
{
  "version": "tr-scope-v1",
  "role": "verifier",
  "requestProfileId": "https://profiles.midnight.network/admissions/v1",
  "purpose": "university-admission",
  "credentialScopeCommitment": "0x...32-byte-hex...",
  "allowedAttributes": ["degree", "issuer"],
  "allowedPredicates": ["age_over_18"],
  "disclosureLevel": "minimum"
}
```

Auditor scope uses the same request fields with `role: "auditor"`. Maintainer
scope is exactly `{"version":"tr-scope-v1","role":"maintainer","registryId":
"tr:midnight:example"}` for the example registry. The role is committed so an
auditor authorization cannot be interpreted as verifier membership.

Scope identifiers are `SHA-256` of UTF-8 RFC 8785 canonical JSON, encoded as
lowercase `0x`-prefixed 32-byte hex. The `version` and `role` fields are part
of the committed object. Object keys and set-valued arrays are sorted
lexicographically before canonicalization; duplicate array IDs are rejected.
V1 permits exact match only: no wildcard, implicit schema-version range,
delegation, or transitive external authorization. Unknown fields, malformed
Unicode, and a version other than `tr-scope-v1` fail closed. Issuer
`schemaVersion` uses an exact three-component numeric version.
External authorization requires a separate recognition record.

The following canonical inputs are required test vectors. Implementations MUST
produce the same scope commitment for the exact JSON object after array
sorting:

```json
{
  "version": "tr-scope-v1",
  "role": "verifier",
  "allowedAttributes": ["degree", "issuer"],
  "allowedPredicates": ["age_over_18"],
  "credentialScopeCommitment": "0x1111111111111111111111111111111111111111111111111111111111111111",
  "disclosureLevel": "minimum",
  "purpose": "university-admission",
  "requestProfileId": "https://profiles.midnight.network/admissions/v1"
}
```

For that verifier input, the canonical UTF-8 text is:

```text
{"allowedAttributes":["degree","issuer"],"allowedPredicates":["age_over_18"],"credentialScopeCommitment":"0x1111111111111111111111111111111111111111111111111111111111111111","disclosureLevel":"minimum","purpose":"university-admission","requestProfileId":"https://profiles.midnight.network/admissions/v1","role":"verifier","version":"tr-scope-v1"}
```

Its commitment is
`0x0c0cfd5d4aa1cb6f3207c4a2b4eea7a8728913173a386799e6a9cc274402b54d`.
The same request with `role: "auditor"` commits to
`0xdf9072c9d749045044d95c632ee9e1640686ab2e176d497144554cb79e8c23b1`.
The maintainer example above commits to
`0x828e4df6eea28455dd5a993bcba67004f2520dfe17faab9cd94eb259180c94ad`.

Implementation clarification (2026-10-05): the former illustrative issuer
digest did not hash the displayed JSON and omitted version and role. The
vectors above replace it; consumers of the former digest must migrate or
redeploy, not reinterpret the old value as a V1 authorization.

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
