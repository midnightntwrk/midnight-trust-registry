# Trust Registry 0.1.0 Reference Profile

Status: proposed release contract
Target: `0.1.0` on `develop`

This profile narrows the [general specification](trust-registry.md) and the
[application evidence protocol](application-evidence.md) to one executable
reference implementation. `MUST` describes the behavior required to claim
0.1.0 conformance. Current code does not yet meet every requirement; the
[milestone issue plan](../plans/milestone-0.1.0-issues.md) tracks the gaps.

## 1. Outcome And Boundary

From a clean checkout, an engineer can run a local Midnight simulator journey
in which a `did:midnight` applicant proves eligibility with a Midnight VC/VP,
an authorized evidence verifier signs a commitment, a quorum of maintainers
approves the exact application, an epoch anchors the decision, and a relying
party independently verifies a current and historical scoped trust answer.
The same journey MUST expose applicant, maintainer, and query operations through
the documented API and local applications. Negative cases MUST fail at the
boundary where the violated rule is enforced.

0.1.0 is a reference profile, not a claim of live network deployment or
production service operation. The simulator is a test double for Midnight
ledger execution. Tests MUST say when finality is simulated. Production
deployment, public multi-tenant hosting, arbitrary DID methods, native
secp256k1/P-256/Ed25519 contract verification, transitive federation trust,
and Ledger 8 synchronous cross-contract calls are outside this milestone.

## 2. Layers And Owners

| Layer | 0.1.0 responsibility | Source of truth |
| --- | --- | --- |
| Governance | Publish versioned eligibility, voting, emergency, audit, and retention rules | Registry policy and its anchor |
| Federation | Optionally authenticate a registry publisher; never grant membership implicitly | External trust chain plus local recognition |
| Registry | Commit application decisions, roles, scopes, evidence hashes, signer sets, and epochs | Trust Registry Compact state |
| Query | Return current/historical decisions with verifiable evidence and explicit failures | Client/API projection of registry state |
| Credential | Verify applicant VC/VP and later issuer VC/status evidence | `midnight-verifiable-credentials` |
| DID | Resolve identifiers and assertion methods, including historical keys | `midnight-did` |

No holder DID, raw credential, raw presentation, private claim, or presentation
activity belongs in registry state, journals, public API responses, or reports.
Status and credential revocation remain with VC status infrastructure.

## 3. Actors And Permissions

An organization MAY play several roles, but each role has its own governed
authorization. A DID alone confers no registry privilege.

| Actor | Can initiate | Must prove / cannot do |
| --- | --- | --- |
| Governance authority | Publish charter, policy, eligibility criteria, and dispute process | Its policy is anchored; it does not bypass on-chain quorum |
| Bootstrap governor | Initialize registry and first maintainer set once | Bootstrap exception is explicit and cannot enroll later members alone |
| Maintainer | Vote on membership, lifecycle, policy, recognition, and epoch actions | DID-bound registered JubJub key, live membership, action-specific quorum; no self-approval |
| Applicant issuer | Request exact credential scope; later issue within an active grant | Applicant DID control and eligible VC/VP; cannot approve itself |
| Applicant verifier | Request exact VP request profile and disclosure limit | Applicant DID control and eligible VC/VP; cannot widen scope by query parameter |
| Applicant auditor | Request an audit profile and later present its mandate to a verifier | Audit grant does not give direct access to holder data or verifier databases |
| Evidence verifier | Verify applicant VC/VP off-chain and sign the canonical result | Active policy-authorized DID assertion key; cannot approve membership |
| External authority / registry | Supply evidence for scoped recognition | Recognition is a peer statement, not a local authorization or maintainer role |
| Holder | Choose whether to present a VC/VP to a verifier | Registry does not observe or log presentation activity |
| Relying party | Query issuer/verifier/auditor grants and validate evidence | Must verify registry, scope, policy, epoch, and time before relying on an answer |
| VC verifier / credential product | Materialize a registry-signed issuer or verifier descriptor | Must pin the registry authority in its own ledger state; a relayer or witness is not an authority |
| Registry operator | Run API, indexer, and local UI | Transport access alone never authorizes a governed mutation |

For the auditor request, the registry answers whether an auditor DID is active
for an exact audit profile, purpose, and disclosure limit. The verifier decides
what it may disclose under the mandate, holder consent, and applicable policy;
actual audit data exchange is off-registry. A verifier MUST NOT treat an audit
grant as blanket access to presentations or personal information.

## 4. Use Cases

| ID | Actor and goal | Preconditions / success evidence | Required rejection |
| --- | --- | --- | --- |
| UC-01 | Governor bootstraps a registry | Registry ID/DID, first maintainer key, policy commitment, and threshold recorded once | Duplicate initialization or missing bootstrap key |
| UC-02 | Authority publishes policy revision | Immutable version and effective window are anchored; prior versions remain resolvable | Reinterpretation of old decisions by a new version |
| UC-03 | Maintainer joins or leaves | Non-bootstrap proposal, independent quorum, activation/revocation event | Self-approval, duplicate signer, insufficient quorum, or removal below threshold |
| UC-04 | Evidence verifier becomes authorized or rotates key | Governed DID, assertion method, public key, suite, policy scope, and validity history | Unknown key, inactive verifier, or signature after key retirement |
| UC-05 | Issuer applies for credential scope | Fresh DID-bound VC/VP attestation, exact scope, policy version, and proposed application | Wrong DID, role, scope, issuer eligibility, status, expiry, or reused challenge |
| UC-06 | Verifier applies for request profile | Exact purpose, credential scope, attributes, predicates, and disclosure limit are proposed | Request wider than the approved profile or unrecognized version |
| UC-07 | Auditor applies for audit mandate | Exact audit profile and mandate evidence are proposed | No mandate, expired mandate, or request outside audit scope |
| UC-08 | Maintainers decide an application | Eligible attestation, policy snapshot, distinct live signer quorum, and decision event | Expired or substituted evidence, self-vote, or stale policy snapshot |
| UC-09 | Maintainers suspend, revoke, or archive | Action-specific threshold and timestamped event; current queries change | Wrong threshold, invalid transition, or silent deletion of history |
| UC-10 | Maintainers recognize external authority | Exact action/resource/authority/registry scope and independent recognition evidence | Recognition used as local issuer, verifier, or admin grant |
| UC-11 | Operator publishes an epoch | State/event/policy roots and signer evidence anchor a bounded view | Invalid root, signer, policy, or unpublished/unfinalized view |
| UC-12 | Relying party evaluates at time T | Active scoped grant, accepted epoch, DID/key history, policy snapshot, and proof all verify | Wrong registry, scope, time, status, Merkle path, or stale epoch |
| UC-13 | Holder presents a credential | Verifier checks VC proof, VC status, issuer grant at issuance, and applicable current policy | Registry lookup used as substitute for VC proof or status |
| UC-14 | Auditor requests verifier information | Verifier can verify the auditor grant and exact request purpose | Blanket data access or holder tracking through the registry |
| UC-15 | VC consumer installs a registry decision | A governed issuer or verifier grant yields a VC-compatible descriptor and authority proof accepted under a pinned local anchor | Witness-supplied authority, wrong network/contract, method/key/scope substitution, stale sequence, or revoked-to-active replay |

## 5. Application And Decision Protocol

1. The applicant authenticates control of its `did:midnight` key and names one
   role, one registry, one exact resource scope, and one application nonce.
2. The evidence verifier challenges the applicant, resolves the DID at the
   verification time, validates the Midnight VC/VP and status using official
   package interfaces, and evaluates the published policy requirements.
3. It produces the [canonical evidence envelope](application-evidence.md),
   with verification/expiry times and policy version, then signs its commitment
   using its authorized DID assertion key. The VP and claims stay off-ledger.
4. The proposal binds applicant DID, role, scope commitment, verifier DID,
   assertion method and key, signature, policy snapshot, nonce, and evidence
   commitment. The contract verifies the signature against a governed active
   key and rejects a replayed live application scope.
5. Distinct active maintainers approve under the threshold selected by the
   action family. Approval binds the same application commitment and immutable
   policy version. Activation is a separate governed transition. Only an
   `active` grant passes authorization queries.
6. A later suspend, revoke, archive, or policy replacement appends an event.
   Historical decisions remain addressable with their original policy and
   signer/key state. The operator publishes a new epoch for a new public view.

The 0.1.0 reference fixture bootstraps three maintainer DIDs and uses a
2-of-3 threshold for ordinary, membership, emergency, and archival action
families. This is a concrete test policy, not a fixed protocol limit. A
maintainer cannot vote on its own admission, suspension, or removal, and no
decision may leave fewer active maintainers than the live threshold. Other
thresholds require their own policy version and positive/negative fixtures.

Application states are `proposed -> authorized -> active`, followed by
`suspended`, `revoked`, `superseded`, or `archived` as allowed by the existing lifecycle
validators. A rejected proposal MUST be terminal or represented by an explicit
rejection event before its scope can be reused; 0.1.0 implementation issues
must settle this currently missing transition. A superseding application gets
a new ID and explicit predecessor reference. No status change is inferred from
a changed API response alone.

The committed record MUST contain enough information to bind the authorization
to the exact evidence commitment, verifier DID/key, policy ID/version, scope,
governance event, and effective interval. Compact verifies supported Schnorr
JubJub signatures. An off-chain `isTrusted` boolean, arbitrary callback, or
witness-supplied key cannot authorize a ledger transition.

## 6. Scope And Historical Decision Rules

Issuer scope is the canonical tuple in
[ADR-0002](../decisions/adr-0002-resource-and-request-profile-canonicalization.md):
credential family, schema ID/version, credential definition, and status method.
Verifier and auditor scope is request profile, purpose, credential-scope
commitment, sorted allowed attributes and predicates, and disclosure level.
Comparison is exact. No wildcard, delegated grant, implicit schema-version
range, or transitive recognition is valid in 0.1.0. Domain, contract adapters,
client, and API MUST share test vectors for the same canonical commitment.

A current trust answer uses the latest accepted finalized epoch and evaluates
the grant at the query time. A historical answer names the evaluation time and
the epoch or ledger view that establishes it; it does not silently substitute
today's policy or keys. For a credential issued at time T, an issuance-time
issuer grant is necessary but insufficient: the verifier also checks the VC
signature and status under VC rules and any current policy restriction. A
revoked issuer cannot issue new credentials. Whether a revocation invalidates
earlier credentials is explicit in the governing policy, never guessed by TR.

Query outcomes MUST distinguish `active`, `not-authorized`, `suspended`,
`revoked`, `superseded`, `out-of-scope`, `expired-policy`, `stale-or-unfinalized-epoch`, and
`invalid-evidence`. A missing or unverifiable historical anchor fails closed.
Query responses include registry ID, role, exact scope, policy ID/version,
effective interval, epoch ID/root, and a verifiable evidence bundle. A listing
or positive boolean without proof is informational only.

## 7. Trusted Anchor For VC Consumers

The current VC [signer-authorization specification](https://github.com/midnightntwrk/midnight-verifiable-credentials/blob/develop/spec/signer-authorization.md)
defines `AuthorizedSignerDescriptor`, `SignerAuthorizationAuthority`, and a
domain-bound authority `Proof` for issuer and verifier roles. It does not use
the older draft's `trustScopeDigest`/`trustEvidenceDigest` transcript. VC owns
core descriptor validation and VC/VP proof decisions; TR owns governed
authorization, DID/relationship evaluation, decision evidence, and
descriptor/authority-proof production. An applicant's eligibility attestation
is input to governance, not an approved signer descriptor.

Issue #79 MUST export a versioned, independently verified TR decision-evidence
bundle: exact registry/network identity, grant role and scope, policy version,
issuer or verifier DID and active method/key, observed DID state version,
effective lifecycle state, accepted epoch, quorum evidence, and inclusion
proof. The builder verifies this evidence before producing a descriptor
candidate. An issuer-only query yields issuer evidence; a verifier query yields
verifier evidence. A presentation product requiring both MUST verify both
independently. Artifact/deployment URLs are discovery metadata unless their
digests are governed and verified.

Issue [#73](https://github.com/midnightntwrk/midnight-trust-registry/issues/73)
MUST map each verified grant to the exact VC `AuthorizedSignerDescriptor` v1
field order and sign its domain-separated decision root with a governed TR
JubJub authority key. The descriptor has non-zero authorization ID, monotonic
decision sequence, state (`active`, `suspended`, or `revoked`), role, exact
`VerificationMethodRef`, public key, positive DID state version, required DID
relationship, non-zero scope commitment, and non-zero policy commitment.
Issuer method requires `assertionMethod`; verifier method requires
`authentication` or `capabilityInvocation`. The VC method ID is SHA-256 of
the canonical Midnight DID fragment and its controller is the exact DID
contract address. Issuer scope is VC `persistentHash<SchemaRef>` for the exact
credential schema; verifier scope is a canonical commitment to the approved
signed request profile. The richer ADR-0002 registry scope is evaluated before
issuing this narrower VC descriptor, never silently widened by it.

The TR-owned `domainCommitment` preimage MUST include Midnight network,
consuming contract, registry ID, and authority identity. The authority proof
binds `persistentHash<Vector<2, Bytes<32>>>([domainCommitment,
descriptorRoot])` using the VC `midnight:vc:signer-auth:v1` context;
`Proof.createdAt` equals the decision sequence, not wall-clock time.
Published vectors MUST match the VC
[signer-authorization conformance vectors](https://github.com/midnightntwrk/midnight-verifiable-credentials/blob/develop/conformance/vectors/signer-authorization.json).
Authority-key rotation is governed and published with overlap/retirement
rules. The signing service MUST only sign a decision already committed under
the required maintainer quorum; its single key is a portable attestation of
that decision, not a replacement for quorum evidence.

A Ledger 8 consumer MUST pin the accepted authority domain, verification
method, and key in its own ledger state, then verify the proof and monotonic
descriptor update before materializing current authorization. A relayer may
deliver a decision but has no authority. Revocation is not synchronous: until
the consumer accepts the newer signed decision it sees its last stored state.
Historical issuance-time authorization remains a separate TR query with an
authenticated epoch; the current VC core descriptor does not prove historical
trust. Recognition or OpenID Federation metadata alone never pins an
authority. A caller-supplied root, descriptor, or `isTrusted` boolean is not
authoritative.

## 8. API, Privacy, And Interoperability

Applicant mutations require an authenticated DID-bound applicant intent with
nonce, expiry, registry, role, and scope. Maintainer mutations require an
authenticated DID-bound intent plus the contract-enforced signer bundle. The
API MUST reject cross-role calls, replay, stale workspace version, and
unauthorized mutation before journal persistence; it MUST NOT synthesize
signatures on behalf of remote callers. Local fixture signing is explicitly
test-only. Read endpoints MAY be public, but must not expose off-ledger VC/VP
payloads or private operator data. A local operator workspace needs atomic
single-writer behavior or a documented fail-closed concurrency guard.

TRQP v2 authorization and recognition queries are read-only projections of
local decisions. Registry metadata, historical proof export, and audit profile
details are named Midnight extensions, not standard TRQP query types. An
OpenID Federation chain MAY authenticate the publisher of registry metadata;
it does not prove a local issuer grant. Recognition of another registry
requires an explicit scoped local decision and verification of that registry's
own evidence. Interoperability never turns a remote registry into a local
maintainer.

## 9. 0.1.0 Exit Gate

- UC-01 through UC-13 have one positive and one rule-specific negative test;
  UC-14 proves authorization boundaries without exchanging audit data.
- The #67 DID assertion-key path is proven inside Compact for issuer,
  verifier, auditor, and non-bootstrap maintainer applications. No deterministic
  fake signature remains in the 0.1.0 conformance journey.
- The API and local applications complete an applicant-to-quorum-to-epoch-to-
  relying-party journey using authenticated actor intents, without direct
  fixture-file edits.
- Current and historical evidence is verified independently, including
  policy/key rotation, suspension/revocation, wrong scope, stale epoch, and
  tampered proof failures. Simulator finality is labeled as simulated.
- UC-15 exports TR decision evidence plus VC-compatible issuer and verifier
  descriptors with authority proofs; a Ledger 8 consumer fixture pins its own
  anchor and rejects wrong domain/key/scope, stale sequence, and revoked
  replay. It labels current-trust versus historical-TR semantics explicitly.
- `./scripts/check-docs.sh`, `./run.sh --light`, `./run.sh integration`,
  `pnpm run demo:smoke`, artifact packing/smoke, and a fresh-checkout 0.1.0
  scenario pass. A release candidate has a source revision, Compact compiler
  version, artifact hashes, and an explicit list of deferred capabilities.

## 10. References

- [ToIP TRQP v2.0 approved specification](https://trustoverip.github.io/tswg-trust-registry-protocol/approved/): authorization and recognition read queries; metadata/description is deferred.
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html): signed entity statements and trust chains for publisher authentication.
- [OpenID Federation for Wallet Architectures draft](https://openid.net/specs/openid-federation-wallet-1_0.html): informative future wallet federation integration.
- [VC signer authorization](https://github.com/midnightntwrk/midnight-verifiable-credentials/blob/develop/spec/signer-authorization.md), [Compact implementation](https://github.com/midnightntwrk/midnight-verifiable-credentials/blob/develop/packages/core/compact/src/credentials/signer-authorization.compact), and [conformance vectors](https://github.com/midnightntwrk/midnight-verifiable-credentials/blob/develop/conformance/vectors/signer-authorization.json): current issuer/verifier authority-anchor contract.
- [Application Evidence Protocol](application-evidence.md), [ADR-0001](../decisions/adr-0001-governance-evidence-and-policy-snapshots.md), and [ADR-0002](../decisions/adr-0002-resource-and-request-profile-canonicalization.md) are the local v0.1 inputs.
- [Research requirements memo](../research/trust-registry-requirements-memo.md) traces the Kanon, MIT issuer registry governance, and other research sources.
