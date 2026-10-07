# Application Evidence Protocol

Status: draft v0.1

The on-chain DID/key check and real VC/VP attestation described here are 0.1.0
requirements, not claims about the current simulator. The simulator signs the
envelope commitment with a test-only JubJub key, but it does not yet resolve
that key from an evidence-verifier DID or verify a VC/VP. The contract currently
binds an evidence hash without verifying the evidence-verifier DID assertion signature.
See the [0.1.0 reference profile](milestone-0.1.0.md) and
[issue plan](../plans/milestone-0.1.0-issues.md).

This profile defines how a party proves eligibility to join a Midnight Trust
Registry. It applies to issuer, verifier, auditor, and non-bootstrap
maintainer applications.

## 1. Boundary

The registry governs the decision to trust a party. It does not parse a VC,
VP, JWT, BBS proof, holder secret, or presentation transcript in Compact.
An authorized evidence verifier performs the VC/VP verification off-chain and
creates a narrowly scoped attestation commitment. The contract verifies the
attestation signer is authorized by the policy and commits the result with the
governed decision.

Raw evidence is retained only by the applicant and evidence verifier according
to their policy and legal obligations. It MUST NOT be written to ledger state,
operator journals, public API responses, or epoch evidence bundles.

## 2. Normative V1 Profile

V1 applicants MUST use a `did:midnight` subject DID and a Midnight VC/VP flow.
The VP MUST prove control of the applicant DID and bind to an application
challenge supplied by the evidence verifier. The verifier checks credential
status, issuer authorization where required, expiry, and the policy-specific
claims below.

| Applicant role | Minimum policy claim | Minimum scope binding |
| --- | --- | --- |
| Issuer | Organization or accreditation authority assertion | Authorized credential scope |
| Verifier | Organization or mandate assertion | Request-profile scope and disclosure policy |
| Auditor | Audit authority or mandate assertion | Audit request-profile scope |
| Maintainer | Governance appointment assertion | Registry id and maintainer role |

The policy MAY require additional claims, multiple credentials, or a recognized
external authority. It MUST identify each acceptable credential family and
evidence verifier by stable identifier.

## 3. Application Evidence Envelope

The evidence verifier produces one envelope per application decision. The
following fields are required before canonical serialization:

```json
{
  "version": "tr-application-evidence-v1",
  "registryId": "tr:midnight:example-registry",
  "applicationId": "tr:application:issuer:acme:2026-07-27",
  "subjectDid": "did:midnight:...",
  "role": "issuer",
  "policyId": "tr:policy:membership",
  "policyVersion": "v1",
  "scopeCommitment": "0x...32-byte-hex...",
  "evidenceVerifierDid": "did:midnight:...",
  "verifiedAt": "2026-07-27T00:00:00Z",
  "expiresAt": "2027-07-27T00:00:00Z",
  "challengeHash": "0x...32-byte-hex...",
  "presentationHash": "0x...32-byte-hex...",
  "claimsCommitment": "0x...32-byte-hex..."
}
```

`presentationHash` and `claimsCommitment` are privacy-preserving commitments,
not the VP or claim values. `scopeCommitment` binds the role-specific issuer,
verifier, auditor, or maintainer scope. All timestamps use RFC 3339 UTC with a
`Z` suffix. Hex values are lowercase and encode exactly 32 bytes.

The `applicationEvidenceCommitment` is `SHA-256` over the RFC 8785 JSON
Canonicalization Scheme representation of the envelope. The evidence verifier
signs this commitment with a policy-authorized assertion key. The signature
and key reference are conveyed to the contract submission path but need not be
included in the commitment itself.

For the Midnight JubJub profile, `keyIdCommitment` is the SHA-256 digest of
the UTF-8 bytes of the absolute DID key reference. The four-field DID Schnorr
digest is computed by the Compact `applicationEvidenceSignatureDigest` pure
circuit from the domain tag `tr:app:evidence:sig:v1`, the key id commitment,
the application evidence commitment, and profile version `1`. This prevents
reuse as an unscoped DID payload signature and binds the signature to the
specific assertion key reference. The signer uses the published DID package's
seed-derived signing helper over that circuit digest. The eventual governed
verification circuit must use the same digest and the registered key. The
signature value is the DID package's 96-byte encoding rendered as lowercase,
`0x`-prefixed hex, with a response scalar below the JubJub group order and
canonical field coordinates. Other encodings are not accepted by this profile.

### Application challenge lifecycle

Before receiving a VP, the evidence verifier issues a fresh 32-byte random
nonce for one application. It gives the applicant the nonce and an expiry no
more than five minutes later. The VP verifier MUST check that the presentation
is bound to that exact nonce and the applicant DID before consuming it. The
envelope's `challengeHash` is SHA-256 of the nonce bytes, not a hash of the
textual hex representation.

The off-ledger challenge store retains only `challengeHash`, an expiry, and a
domain-separated commitment to registry id, application id, subject DID,
evidence-verifier DID, role, policy id/version, governed resource type/id, and
scope commitment. It MUST
derive or validate the scope commitment against the versioned canonical
role-specific scope object before issuing the challenge; a valid-length opaque
hash alone is insufficient. Registry, application, and policy IDs in a
challenge binding MUST use canonical lowercase spelling. The scope role MUST
match the application role, and a maintainer scope's registry ID MUST equal
the challenge registry ID. The separately governed resource MUST match the
role-specific scope: an issuer's credential family, verifier/auditor request
profile, or maintainer registry. Its identifier is not the scope commitment.
The scope object is not stored in the challenge record, but is supplied again
when the challenge is consumed and checked against the same commitment. It MUST
perform collision-safe insertion, replacement of an earlier live challenge
for the same binding, and check-and-delete atomically across all API replicas.
The newest challenge supersedes the old one for that binding. Any future public
issuance route MUST authenticate the applicant before it permits replacement;
otherwise a third party could invalidate the applicant's outstanding challenge.
Consumption succeeds only
when the submitted nonce hashes to the envelope value, the complete binding
matches, and the challenge has not expired; retry, mismatch, and expiry all
return the same rejection category. A failed binding check does not consume a
valid challenge. The raw nonce, VP, and holder data MUST NOT enter a journal,
ledger, public response other than the initial challenge issuance response,
or evidence bundle.

Application evidence validation also requires the envelope `challengeHash` to
match the hash issued for that application's governed context, even if an
attacker recomputes the envelope commitment. The simulator currently uses a
deterministic challenge fixture; it is not a production nonce source.
After successful atomic consumption, the challenge service returns the verified
hash as canonical lowercase hex derived from the nonce; callers MUST use that
return value as the proposal's expected `challengeHash`, not the untrusted
submission field. The evidence validator compares challenge hashes by byte value,
so accepted hex casing does not change challenge identity or the signed envelope.
The same byte-value comparison applies to `scopeCommitment`.

The API package has a reference challenge-to-proposal intake seam. It checks
the complete canonical governed binding before calling a trusted VP verifier,
consumes the challenge once only after the VP nonce and subject DID match, and
passes a signed evidence envelope to an injected proposal callback. The seam
does not itself implement the official VC verifier or a public route. The
simulator's synthetic application-evidence envelope still uses a resource-ID
commitment under `scopeCommitment`; that value MUST NOT be interchanged with
the canonical role-specific scope digest. Proposal integration must replace
the stand-in and test each applicant role before this boundary is complete.

The reference API package exposes an in-memory store for local tests only. It
caps live entries and schedules expiry cleanup even without another request;
these bounds do not replace distributed durability or abuse controls. A
public issuance route requires a durable atomic store, applicant authentication,
abuse controls, and a retention/cleanup policy; those are not delivered by
this reference store. Challenge expiry uses the evidence verifier's off-ledger
clock. Invalid clock readings and store capacity exhaustion are operational
errors, not invalid applicant challenges. It is not a claim that the Midnight
contract has a datetime primitive.

## 4. Contract Inputs And Checks

The governed approval transition consumes:

- `applicationEvidenceCommitment`
- `policyId` and `policyVersion`
- `evidenceVerifierDid` and its assertion key reference
- `verifiedAt` and `expiresAt`
- evidence-verifier signature over the commitment
- the maintainer signer bundle required for the decision family

The contract MUST reject a transition when any of the following holds:

- the application id, subject, role, registry, policy, or scope differs from the
  application being approved;
- the evidence verifier is not active for the policy at `verifiedAt`;
- the evidence is not yet valid or is expired at approval or activation time;
- the signature is invalid for the verifier key reference;
- the required maintainer quorum is not satisfied; or
- the same live authorization scope already exists for the subject.

The contract MUST retain the commitment, policy snapshot, verifier identity,
verification window, and governance event reference in append-only state.

## 5. Privacy And Retention

The envelope MUST NOT contain holder DID, credential subject claims unrelated
to the applicant, credential serial numbers, revocation witnesses, or a
correlatable presentation identifier. A verifier MAY retain the full evidence
off-ledger only for the retention period named by the policy. Epoch evidence
exports contain the envelope commitment and decision context only.

## 6. Extensions

Non-Midnight DID methods and secp256k1, secp256r1, or Ed25519 assertion keys
are extension paths. A policy enabling one MUST name the accepted DID method,
key encoding, signature suite, evidence verifier, and migration or retirement
rule. No extension is accepted by default in v1.

## 7. Required Negative Fixtures

Every role fixture set MUST include a valid envelope plus missing, expired,
wrong-subject, wrong-role, wrong-policy, wrong-scope, unauthorized-verifier,
and invalid-signature cases. Fixtures contain commitments only and no raw VP.
