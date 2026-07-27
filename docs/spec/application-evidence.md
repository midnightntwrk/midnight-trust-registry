# Application Evidence Protocol

Status: draft v0.1

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
  "policyVersion": "1",
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

## 4. Contract Inputs And Checks

The governed approval transition consumes:

- `applicationEvidenceCommitment`
- `policyId` and `policyVersion`
- `evidenceVerifierDid` and its assertion key reference
- `verifiedAt` and `expiresAt`
- evidence-verifier signature over the commitment
- the maintainer signer bundle required for the decision family

The contract MUST reject a transition when any of the following holds:

- the application subject, role, registry, policy, or scope differs from the
  application being approved;
- the evidence verifier is not active for the policy at `verifiedAt`;
- the evidence is expired at approval or activation time;
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
