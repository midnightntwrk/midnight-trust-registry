# Recognition Accreditation VC/VP Delivery Plan

Status: implementation plan for issue #78, 2026-10-14

Local implementation checkpoint: the domain anchor/claims schema and private
recognition accreditation VP verifier have signed-fixture positive and negative
tests. The joined simulator demo uses the same fixture to verify the accreditor
VC, authority VP and separate authority DID assertion, consumes an exact-tuple
challenge once, and commits combined verified evidence through Compact. The
status decision port now has a challenge-bound, five-minute JubJub-signed
status-authority attestation adapter; the demo still fetches that attestation
from a deterministic fixture, not a live status registry. The accreditor anchor is now a
maintainer-quorum-approved governance-policy preimage checked against the
current Compact policy commitment in the private challenge path. An opt-in,
authenticated private HTTP route now exercises challenge and redacted evidence
verification; it is not mounted by the CLI and is not public intake.

The existing DID-only convenience path proves authority key control, not
accreditation. The composed simulator path adds independent signed VC/VP proof
checks while keeping recognition separate from local issuer, verifier, and
maintainer membership.

The simulator currently revises the governance policy content through the
existing quorum-signed policy/threshold revision circuit while retaining the
same thresholds. A dedicated accreditor-anchor management action, durable
policy-source adapter, and live status-registry evidence adapter remain follow-on work. Public
intake must not accept a caller-provided policy record or ledger commitment.

## Decision Boundary

The default 0.1.0 accreditation input is a Midnight VC presented by the
recognized authority through a Midnight VP. The VC issuer is an accreditor,
not the applicant authority. The authority DID assertion and the accreditor
VC/VP are two separate proofs and MUST name the same authority DID, external
registry, and exact resource scope. The applicant cannot choose its accreditor
trust anchor in the submission.

A locally governed accreditation-anchor policy MUST identify the permitted
accreditor DID and assertion method, credential family/schema, status registry
and status authority, target registry, external registry, scope, policy
version, and effective interval. Its canonical commitment must be part of the
governance policy preimage and the redacted recognition evidence commitment.
Maintainer signatures must bind the latter through the existing Compact
proposal payload. A policy lookup supplied by the applicant, a self-signed
Federation trust-chain terminus, or a generic callback returning `true` is
not an accreditation proof.

## Verification Pipeline

1. Resolve the active governed anchor policy and issue a one-use recognition
   challenge for the exact tuple. The existing challenge store is the atomic
   replay boundary; production replicas require durable shared storage.
2. Parse the VP and credential body under a recognition-specific schema. The
   credential claims must name the authority DID, external registry ID,
   resource type/id, accreditation family, issuer DID, and status handle.
   Reject unknown or ambiguous scope fields rather than projecting them away.
3. Resolve the accreditor's current Midnight DID assertion method and the
   authority's authentication method. Verify the VC issuance proof, VP proof,
   nonce, holder binding, body roots, expiry, and registry-bound status binding
   using the installed VC/DID packages. Verify active credential status from
   the policy-pinned status source at the trusted evaluation instant; a
   fixture-only status decision cannot authorize public intake. The local
   signed-status profile pins the status authority DID assertion method, exact
   handle and challenge, a bounded observation interval, and the observed DID
   state version. It authenticates the authority's statement but does not
   prove the authority's underlying status-ledger state.
4. The authority assertion signs an applicant-computable commitment to the
   exact submitted VP, not the registry's later status decision. Verify this
   separate DID assertion with the same tuple and challenge. Consume the
   challenge only after both proofs and policy/status
   checks pass. A failed proof must leave it usable, while a concurrent valid
   replay must lose the atomic consume race.
5. Commit a redacted combination of verified authority assertion evidence and
   verified accreditation evidence, including VP/claims and anchor-policy
   commitments, observed
   accreditor/authority DID state versions, status decision commitment, and
   evaluation instant. Do not store raw VC/VP bodies, claims, or holder data in
   the ledger, operator journal, or public response.
6. The active local evidence verifier signs the resulting scoped recognition
   proposal; the required maintainer quorum signs it independently. Compact
   commits the evidence hash and proof snapshot. Approval/activation recheck
   current policy and verifier-key eligibility. Public recognition remains a
   scoped peer statement and never becomes a local membership grant.

## Implementation Slices

- Add canonical accreditation-anchor policy and recognition-claim schemas to
  the domain package, with strict negative vectors and a versioned commitment.
- Extract the common Midnight VC/VP proof checks from application intake into
  a role-neutral helper. Keep existing application behavior and tests intact;
  recognition supplies its own claims and anchor/status policy checks.
- Add a concrete recognition accreditation verifier and a deterministic
  independently signed VC/VP fixture with valid, wrong issuer/key, wrong
  authority/registry/scope, expired, revoked, stale status, and replay cases.
- Compose both proofs and the atomic challenge in private API intake. The
  private path now resolves the anchor against an active Compact policy
  commitment rather than accepting a raw anchor. The optional HTTP port
  supplies policy and status from the server, not the request, and returns no
  durable acceptance receipt. Fail closed unless a trusted ledger policy
  reader and live status adapter are configured; do not mount a production
  public route before durable admission and atomic write-boundary checks exist.
- Carry the redacted commitment through Compact proposal, epoch evidence,
  public query and TRQP parity. Extend the joined demo and full integration
  suite. Run fresh Compact proving once at the publication checkpoint.

## Acceptance And Limits

Issue #78's UC-10 path needs a positive signed accreditation VP and negative
cases for an untrusted accreditor, inactive status, wrong exact scope,
invalid DID relationship, replay, insufficient maintainer quorum, and
recognition-as-local-authorization. Verify the same redacted commitment from
intake through ledger and public evidence. This is local simulator conformance,
not Midnight network finality. `did:web`, Ed25519/P-256/secp256k1 on-chain
verification, transitive Federation trust, and a generic external-registry
trust bridge remain separate adapters with explicit trust-anchor policies.
