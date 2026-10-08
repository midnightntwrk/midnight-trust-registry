# ADR-0003: Composite Issuer Resource Identity

Status: accepted for the unreleased 0.1.0 profile

Date: 2026-10-08

## Context

An issuer scope contains a credential family, schema, exact schema version,
credential definition, and status method. The governed resource has a separate
type and ID. Using only `1.0.0` for `schemaVersion`, or only a status-method
name for `statusMethodRequirement`, gives distinct scopes the same on-ledger
`(resourceType, resourceId)` key. A challenge can then name one scope while
the contract authorization and current lookup name another.

## Decision

Every issuer resource type (`credentialFamily`, `schema`, `schemaVersion`,
`credentialDefinition`, and `statusMethodRequirement`) is scoped to the entire
exact canonical issuer scope from ADR-0002. A grant to one family does not
implicitly grant another schema, version, definition, or status method in that
family. There is no global schema-version or status-method grant in 0.1.0.

For a validated issuer scope `S` and one of the five resource types `T`, define:

```text
C = computeAuthorizationScopeCommitment(S)  // lowercase 0x-prefixed SHA-256
P = JSON.stringify(["tr:issuer-resource:v1", T, C])
resourceId = "tr:issuer-resource:v1:" + lowercaseHex(SHA-256(UTF-8(P)))
resourceIdCommitment = SHA-256(UTF-8(resourceId))
```

For the exact issuer scope vector in ADR-0002 and `T = credentialFamily`, the
resource ID is
`tr:issuer-resource:v1:e4edbae272fdd78e6ceccde9e4018528ffa418094eeddae33782738293b3dd8d`
and its Compact commitment is
`0xf4d2231e9d0bcb65bf7a39ab5b5893a4db0e199f209ee27ec1834344aee7162f`.

The ordered array has no optional or unordered members, so its JSON spelling
is canonical for these ASCII strings. The type is included even though the
contract also receives `resourceType`; this prevents cross-type interpretation
of an ID outside the contract. The textual `resourceId` satisfies the scoped
identifier profile and is the exact value placed in the signed application
envelope, challenge binding, API request, authorization evidence, and lookup.
The 32-byte `resourceIdCommitment` is the value passed to Compact. The
contract's existing `issuerAuthorizationScopeKey(subjectDidCommitment,
resourceType, resourceIdCommitment)` then distinguishes both subject and
composite resource. The registry does not need to parse a scope in Compact.

Application intake MUST recompute `resourceId` from the validated canonical
scope and type before issuing or consuming a challenge. A signer or API client
MUST NOT supply a bare version or status-method name as an issuer resource ID.
The on-chain contract still governs opaque 32-byte commitments; it relies on
the authenticated intake boundary to attest that the committed bytes came from
this canonical scope. A raw contract caller bypassing that boundary can create
an opaque authorization, but cannot claim it corresponds to a canonical 0.1.0
issuer resource without the matching scope and evidence.

## Consequences

Changing any issuer-scope field creates a different resource ID for all five
types. Existing fixtures and API callers must derive IDs rather than copying
one scope field. This is migration-free because the registry is unreleased;
there is no legacy bare-value key to support. Cross-resource tests must use
the same subject, schema version, and status method with differing schema or
family values, and prove coexistence plus failed substitution in challenge
intake, contract authorization, historical evidence, and current lookup.

## Rejected Alternatives

- Bare schema versions and status methods: collide across scopes.
- Type-only domain separation: prevents cross-type reuse but not two schemas
  with the same version or method.
- Prefixing a human-readable family or schema ID: requires another escaping
  profile and risks ambiguous concatenation; the canonical scope commitment
  already gives a fixed, versioned preimage.
