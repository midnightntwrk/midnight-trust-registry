# Application Evidence Protocol

Status: draft v0.1

The issuer, verifier, auditor, and maintainer reference paths register a policy-scoped JubJub
assertion key and verify its signature over the exact governed proposal in
Compact. The local
simulator also signs the envelope commitment with a test-only JubJub key. It
does not resolve either key through a DID document or verify a real VC/VP.
On-chain DID resolution and real VC/VP attestation
remain 0.1.0 requirements, not claims about the current simulator.
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
  "scopeCommitment": "0xf9d7d610bba907f28353425136f9ba2bc65d5925421371fc7580716029b3c6c8",
  "governedResource": { "type": "credentialFamily", "id": "tr:issuer-resource:v1:e4edbae272fdd78e6ceccde9e4018528ffa418094eeddae33782738293b3dd8d" },
  "evidenceVerifierDid": "did:midnight:...",
  "verifiedAt": "2026-07-27T00:00:00Z",
  "expiresAt": "2026-07-28T00:00:00Z",
  "challengeHash": "0x...32-byte-hex...",
  "presentationHash": "0x...32-byte-hex...",
  "claimsCommitment": "0x...32-byte-hex...",
  "statusDecisionCommitment": "0x...32-byte-hex..."
}
```

`presentationHash`, `claimsCommitment`, and `statusDecisionCommitment` are
privacy-preserving commitments,
not the VP or claim values. `scopeCommitment` binds the role-specific issuer,
verifier, auditor, or maintainer scope. All timestamps use RFC 3339 UTC with a
`Z` suffix. Hex values are lowercase and encode exactly 32 bytes.
For the Midnight VC/VP reference path, `statusDecisionCommitment` is SHA-256
over canonical JSON of the domain tag
`tr:application:verified-status-decision:v1`, the verified signed status
statement (including its proof), and the status authority DID state version ID.
The verifier computes it only after checking the governed status registry and
authority key, credential binding, challenge, active flag, freshness, and
JubJub signature. It binds the decision used at intake but is not a public
non-revocation proof: independent later audit requires access to the private
signed statement and authenticated historical DID state. The registry does
not store the statement or VP.
The governed resource type and ID are signed separately because one issuer
scope can authorize several resource kinds. Proposal intake MUST compare both
fields against the proposed resource, not only the scope commitment.
For issuer applications, the resource ID is the type-separated composite of
the entire canonical issuer scope, not the bare schema version or status-method
name. All five issuer resource types use the same encoding defined in
[ADR-0003](../decisions/adr-0003-composite-issuer-resource-identity.md).
For verifier and auditor applications, the `requestProfile` governed-resource
ID is the role-separated composite of the complete canonical request scope,
not the bare profile ID. The signed scope commitment determines that ID as
specified in [ADR-0004](../decisions/adr-0004-composite-request-scope-identity.md).

The `applicationEvidenceCommitment` is `SHA-256` over the RFC 8785 JSON
Canonicalization Scheme representation of the envelope. The evidence verifier
signs this commitment with a policy-authorized assertion key for off-chain
intake. The signature and key reference need not be included in the commitment
itself. For issuer, verifier, auditor, and maintainer proposals, the evidence verifier separately signs the governed
proposal payload bound to the evidence commitment, registered verifier key,
and active policy snapshot. This second signature is checked in Compact; an
intake signature alone cannot authorize a proposal.

For the Midnight JubJub profile, `keyIdCommitment` is the SHA-256 digest of
the UTF-8 bytes of the absolute DID key reference. The four-field DID Schnorr
digest is computed by the Compact `applicationEvidenceSignatureDigest` pure
circuit from the domain tag `tr:app:evidence:sig:v1`, the key id commitment,
the application evidence commitment, and profile version `1`. This prevents
reuse as an unscoped DID payload signature and binds the signature to the
specific assertion key reference. The signer uses the published DID package's
seed-derived signing helper over that circuit digest. The issuer proposal
uses `issuerEvidenceBoundProposalPayloadHash` and
`issuerProposalEvidenceSignatureDigest`; the verifier proposal uses the
role-separated `verifierEvidenceBoundProposalPayloadHash` and
`verifierProposalEvidenceSignatureDigest`; the auditor proposal uses
`auditorEvidenceBoundProposalPayloadHash` and
`auditorProposalEvidenceSignatureDigest`; the maintainer proposal uses
`maintainerEvidenceBoundProposalPayloadHash` and
`maintainerProposalEvidenceSignatureDigest`. Each pair binds the complete
role-specific authorization payload, evidence-verifier authorization and key
identifiers, registry identifier, and active policy commitment and version. The contract verifies
this distinct digest against the active registered JubJub key. The intake
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

The off-ledger challenge store retains only `challengeHash`, trusted issuance
and expiry instants, a registry/application identity hash for replacement, and
a domain-separated binding commitment to registry id, application id, subject DID,
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
perform collision-safe insertion, same-binding replacement, and
check-and-delete atomically across all API replicas. A live challenge for the
same registry/application pair but a different subject, scope, policy, or
governed resource MUST NOT be replaced without an authenticated applicant
transition. The reference store rejects such changes; a future public route
MUST authenticate the applicant before allowing either replacement or
same-binding retries, so a third party cannot invalidate an outstanding
challenge.

The 0.1.0 reference intake profile permits zero clock skew between the
challenge service and its trusted evaluation instant. A VP verification time
MUST be at or after the stored challenge issuance instant, strictly before
the stored challenge expiry, and no later than the trusted evaluation instant.
The evaluation instant itself MUST be inside that half-open challenge window.
The signed evidence expiry MUST be after verification and no more than 24
hours later. Evidence may remain valid after the five-minute challenge expires;
the challenge proves VP freshness, whereas the evidence window bounds later
governed approval. The service MUST read the window from the challenge store,
validate its numeric issuance and expiry instants, and fail closed if that
window is malformed; it MUST NOT use a caller-supplied issuance response or
verifier timestamp as the window. Canonical envelope hashing remains available
for structurally valid historical envelopes even when the current intake
profile would reject their validity duration. A
deployment requiring nonzero skew must define and test that tolerance as an
explicit policy value before changing this profile. A backward challenge
clock jump is an operational failure, not a reason to accept earlier evidence.
Every invalid time window MUST fail before nonce consumption and leave the
live challenge available for a corrected attempt.

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

An issuer, verifier, auditor, or maintainer applicant MAY register a pending
application by signing a distinct `apply` mutation intent with its Midnight
DID key. The intent MUST commit to the canonical role scope, governed resource,
application ID, and requested authorization ID; a successful registration
creates only an off-ledger pending record. The server derives the binding from
the current trusted workspace policy and verifier configuration, not from
applicant-provided policy or binding fields. `GET
/v1/application-evidence/:applicationId/binding` MUST authorize the applicant
against that pending record before returning the binding. Registration MUST
reject stale workspace context, reused nonces, duplicate IDs, and duplicate
active subject/scope applications. A production host MUST persist those checks
atomically, refresh policy and verifier authority from trusted sources, and
recheck them when VP evidence is persisted. Neither a pending registration nor
a VP receipt constitutes a governed Compact proposal or active membership.

When one HTTP host exposes both VP intake and governed proposal routes, it MUST
configure an accepted-application admission port. Proposal preparation and
submission MUST resolve the signed pending record and accepted VP evidence
separately by the evidence application ID and
match the signed requested authorization target and role, the server-owned binding,
the exact redacted signed evidence, and its validated receipt. Missing,
substituted, or unreceipted evidence MUST fail before governance signing work.
This off-ledger join does not replace the proposal circuit's current-policy,
verifier-key, evidence-signature, quorum, and sequence rechecks. The host must
persist the accepted record atomically with the receipt and make it available
only after successful VP intake; the in-memory demo is not durable.
An applicant-authorized `GET /v1/application-evidence/:applicationId/receipt`
MAY recover the accepted redacted signed evidence and receipt after a lost
submission response. The host MUST authorize the applicant before looking up
the record, require the receipt's evidence commitment to match the canonical
evidence commitment, and return no raw VP. It MUST NOT reverify the VP, consume
another nonce, or create a second accepted record. An absent receipt means only
that no acceptance was found in that host's accepted store; it is not proof that
an in-flight submission failed and MUST NOT cause automatic resubmission.
The local signed issuer/verifier/auditor/maintainer reference derives registration preflight and
snapshots from one Compact simulator, then carries one accepted VP through
2-of-3 maintainer proposal, decisions, and epoch publication. Issuer, verifier,
and auditor grants reach independently verified public evidence lookup;
maintainer enrollment is checked against the Compact membership record.
For registry epoch publication, `POST /v1/governed/epochs/prepare` returns the
current ledger-derived registry ID, policy commitment, action kind, payload
hash, sequence, epoch ID and roots. Each maintainer signs that exact
policy-bound action outside the API host. `POST /v1/governed/epochs/publish`
recomputes the context, returns 409 for a stale submission, and forwards the
provided signatures to a Compact-backed publication port. A missing port is
503; invalid quorum or signatures are rejected without a ledger event. The
returned epoch MUST be the ledger-recorded commitment, not a caller-supplied
root. The local simulator projects that exact registry epoch into the query
snapshot. Its `currentEpoch` MUST identify the Compact ledger's current epoch
record; sorting projected epochs by their declared time is insufficient when
per-grant projection publishes another epoch after the registry epoch.
Per-grant evidence bundles may still be created by fixture
signing during projection. This reference path is not network finality and
does not yet prove that every published evidence epoch used external signers.
For quorum changes, `POST /v1/governed/policy/thresholds/prepare` and
`/submit` carry the old-policy signer context and requested thresholds.
After Compact accepts the revision, the evidence-verifier key must be
registered under the new policy through
`POST /v1/governed/policy/evidence-verifier/prepare` and `/submit`, using
fresh external signatures. Both actions recheck current ledger state; the
second action is not automatically signed or atomic with the first. Until it
succeeds, new application evidence is not authorized by the revised policy.
Private file adapters persist pending records, spent nonces,
challenge hashes, and accepted redacted evidence across store restarts, but
the two files and Compact ledger have no shared transaction. An optional
governed proposal resolution port can recover a lost HTTP submit receipt by
reading the Compact proposal evidence record and matching its evidence
commitment to the admitted application. The API package exports
`resolveCompactProposalObservation` for issuer, verifier, auditor, maintainer,
and recognition proposal records. The recognition HTTP resolution route
requires private request authorization and the exact accepted accreditation
receipt, application binding, and evidence commitment. It may recover an
observed event after the receipt window has passed, but cannot authorize a new
proposal. The applicant portal exposes the authority challenge, externally
signed assertion plus accreditation VP submission, accepted-receipt lookup,
and proposal recovery only through an authenticated same-origin host. It
clears the raw submission form after use and does not store the VP in browser
storage. Recovery sends only the accepted receipt ID and evidence commitment,
not the underlying VP or a token in the URL or browser storage.
The caller MUST provide an independently finalized ledger view and the expected registry
ID; the resolver checks the latter against Compact state. An unconfirmed
transaction result is not a substitute. A `not-observed` response is
ambiguous, not a failed-transaction proof, and MUST NOT trigger automatic
resubmission. Simulator tests show that an unfinalized write remains
unobserved until the supplied finalized view advances. A production finality
reader, authoritative host, and cross-store recovery protocol remain open.

The API package has a reference challenge-to-proposal intake seam. It checks
the complete canonical governed binding and performs a non-consuming live
challenge lookup, including the trusted stored time window, before expensive
VP verification. That lookup is only a cheap
preflight; atomic check-and-delete remains the replay boundary. The trusted
VP verifier receives the full parsed binding (including role, scope, policy,
and governed resource), nonce, and evaluation time. It MUST evaluate those
fields rather than trusting a scope fixed when the verifier was constructed,
and return the evaluated canonical scope commitment. Intake rejects a result
whose commitment differs from the live challenge before it spends the nonce.
The intake then consumes the challenge once only after the VP nonce and subject
DID match, and
passes a signed evidence envelope to an injected proposal callback. The seam
does not itself implement the official VC verifier. The API exposes optional
`POST /v1/application-evidence/:applicationId/challenges` and
`POST /v1/application-evidence/:applicationId/submissions` routes only when a
trusted host injects an application VP port. That port MUST authenticate and
authorize the applicant against the pending application before request-body
parsing or VP work; authentication by an external proxy alone is insufficient.
The server derives binding and authorized verifier policy from the host, never
from the applicant's request. It rechecks both just before evidence persistence;
the host MUST atomically recheck pending status and policy at persistence. These
private routes do not advertise wildcard cross-origin access. Same-origin
hosting or a narrowly configured authenticated proxy, plus CSRF protection
where cookie credentials are used, is required for a browser flow. The
packaged CLI does not inject the port, so it returns 503. An
integration-only test uses the real challenge service and JubJub signing with
all four simulator proposal circuits; the simulator verifies the consumed
challenge hash and canonical scope commitment supplied by the trusted intake
context. Its separate deterministic challenge fixture still uses the same
canonical scope commitment, but MUST NOT be used as a production nonce source.
Production use still needs a host implementing genuine family/status VP
verification, abuse controls, durable atomic challenge storage, and atomic
pending-application persistence. The reference fixture family parses submitted
proof JSON, derives credential and presentation body roots from the submitted
bytes, checks their published VC/VP signatures against Midnight DID keys, and
derives role scope from the signed fixture credential body. The signed fixture
presentation body names that credential body root and holder DID; a separately
valid presentation for a different credential is rejected before eligibility.
By default, its family verifies a five-minute, nonce- and credential-root-bound
status attestation against a pinned status registry and assertion method. The
fixture pins these from its signed credential body; production MUST derive the
anchor from a verified governed issuer status-policy binding instead. The
authority's current Midnight DID
assertion key verifies a domain-separated JubJub signature. The registry,
method, handle, credential root, nonce hash, active flag, observation window,
and DID state version are all checked before returning an expiry bound.
Explicit `statusDecision` overrides exist only for negative test cases. The
fixture still uses test-only issuer eligibility and a deterministic attestation
fetcher, accepts only its fixture credential-body format, and MUST NOT be
mounted as a public verifier. A signed authority assertion is not an
independent status-registry root or non-revocation proof.

The application VP family interface MUST return the full governed issuer
status-policy binding from issuer eligibility; it MUST NOT return a bare
boolean. The verifier compares that binding's status registry with the signed
credential binding before consulting status, then passes the exact binding,
nonce, and evaluation instant to the status source. A reference eligibility
adapter verifies current active issuer decision evidence through caller-owned
finality-aware registry and DID readers, then matches the presented issuer DID,
assertion method public key, and status-registry ID. The host selects the
permitted issuer resource and applicant roles; the credential does not select
its own trust anchor. The reader and attestation fetcher still need production
implementations, and the deterministic fixture's issuer grant is not governed.
The simulator composition test additionally binds a signed fixture VC/VP to
an independently verified active issuer decision and a challenge-bound status
attestation; it rejects a current grant reported as suspended. This proves the
reference wiring locally, not production finality or live revocation.

The reference API package exposes an in-memory store for local tests and a
bounded file-backed store for a single local deployment. The in-memory store
caps live entries and schedules expiry cleanup; the file-backed store uses
private atomic file replacement and a cross-process lock for one-use consume,
and prunes expired records during writes. Neither supplies distributed storage,
crash-durable commits, applicant authentication, abuse controls, or a complete
retention/cleanup policy. A public deployment MUST provide and test those
properties as appropriate to its failure model. Challenge expiry uses the evidence verifier's off-ledger
clock. Invalid clock readings and store capacity exhaustion are operational
errors, not invalid applicant challenges. It is not a claim that the Midnight
contract has a datetime primitive.

## 4. Contract Inputs And Checks

The issuer, verifier, auditor, and maintainer governed proposal transitions consume:

- `applicationEvidenceCommitment`
- the active policy commitment and version
- the governed evidence-verifier authorization ID and assertion key reference
- the evidence-verifier signature over the proposal-bound commitment
- the maintainer signer bundle required for the decision family

These four contract paths MUST reject a proposal when any of the following holds:

- the application id, subject, role, registry, policy, or scope differs from the
  signed proposal payload;
- the evidence-verifier key is not active under the current policy snapshot;
- the signature is invalid for the verifier key reference;
- the required maintainer quorum is not satisfied; or
- the same live authorization scope already exists for the subject.

Each role retains the commitment, policy snapshot, evidence-verifier DID and key
commitments, verifier signature, and governance event reference in a proposal
evidence record keyed by its authorization ID. This is historical evidence:
subsequent verifier-key suspension does not delete a prior proposal record. The
envelope's `verifiedAt` and `expiresAt` remain off-ledger data committed by its
canonical hash. The intake service MUST validate the evidence window against a
trusted off-ledger clock when accepting the application and again before any
later approval or activation. Compact cannot independently parse the envelope
from its hash or compare its timestamps with a trusted wall clock. Therefore
the reference implementation MUST NOT claim that expiry or verifier activity at historical
`verifiedAt` was proven by the contract. A sequence-bound validity rule or an
authenticated time attestation, with an on-ledger verification-window record,
is required before the broader on-chain expiry rejection target is met.

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
