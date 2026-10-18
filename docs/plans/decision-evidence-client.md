# Verified decision evidence for VC consumers (#79)

Status: implementation profile. No current client response is a VC signer
descriptor or an independently authenticated DID observation.

## Trust boundary

`verifyTrustRegistryEvidenceBundle` currently checks a supplied epoch record,
one supplied maintainer public key, the policy snapshot, and an inclusion
proof. Its `EpochAnchorVerificationContext` explicitly leaves the provenance
of the epoch record and public key to the caller. The bundle has no proof of a
specific DID method, relationship, or DID state version. Therefore neither
that function nor an API `active` response may produce a trusted signer
descriptor. A positive decision requires two independently accepted anchors:
the registry epoch and the subject DID state.

`assertDecisionEvidenceMatchesAcceptedEpoch` now compares every claimed epoch
identity, root, publication reference, validity window, and threshold to a
separately supplied accepted context. The caller must authenticate that
context; this comparator does not verify publication signatures, quorum,
finality, currentness, or the DID state. It therefore cannot produce a
positive signer descriptor on its own.
`assertDecisionEpochPublicationSignatures` additionally reconstructs the
Compact epoch payload, verifies each distinct active maintainer's
policy-bound JubJub signature, and matches the ordered signer-set event hash.
Its accepted epoch, threshold, registry/epoch commitments, first signer, and
active-key set must all come from authenticated ledger state at publication;
the helper does not fetch or authenticate them. It also does not prove that
the decision grant remains current after the epoch.
In this v1 profile, each absolute maintainer DID method ID must hash to its
on-ledger key ID commitment; a matching public key alone cannot relabel the
signer as another DID method.

`assertDecisionEvidenceConsistentWithSuppliedContext` composes accepted-epoch
equality, full publication signatures and event hash, grant inclusion/policy/
scope/window checks, and DID-method observation matching. The selected
sequence and evaluation time arrive as one caller-authenticated decision-point
observation, not separate query inputs. That observation must also identify
the current authorization for the exact scope at the selected sequence, with
its active status and lifecycle event root matching the included grant. This
rejects a historical epoch leaf after a later replacement or lifecycle change;
the caller must authenticate the current-scope read, not copy it from the
candidate bundle. Midnight does not itself establish a
wall-clock timestamp for a sequence. This helper cannot authenticate their
mapping. It returns no descriptor or authorization boolean: the caller must
authenticate the accepted epoch, maintainer set, joint decision point/current
scope, and DID
observation, and establish finality and currency separately.
Local composition fixtures cover issuer assertion and verifier authentication
methods with two real publication signers, exact request-profile rejection,
and fail-closed suspended, revoked, superseded, and archived grant selection.
The joint decision-point observation must also supply the active policy root
at the selected sequence. An epoch whose policy has since been superseded
cannot authorize a new current decision even if its included grant remains
active. The caller authenticates that observation; comparing the roots does
not establish provenance.

The v1 profile supports `did:midnight` and the published DID package's native
SchnorrJubjub method. Opaque JWK methods are not silently converted to a
JubJub point. Other suites require a separately specified verification path.

The optional read-only `GET /v1/decision-evidence/{role}/{id}` endpoint may
return an issuer or verifier `tr-decision-evidence-v1` bundle from an injected
finalized source. It is disabled with 503 when no source is configured, rejects
malformed or cross-registry/role/authorization records, and marks a successful
response `verification: client-required`. The API performs structural parsing
only. Neither an HTTP 200 nor the source's assertion of finality replaces
`verifyDecisionEvidenceWithTrustedReaders` with independently authenticated
accepted epoch and DID observations. Consumers MUST NOT create VC signer
descriptors directly from this endpoint's response.
`verifyDecisionEvidenceFromApi` is the client composition helper: it fetches
the envelope without caching, requires the `client-required` marker and exact
grant ID/role, then calls `verifyDecisionEvidenceWithTrustedReaders`. It
accepts only HTTPS or loopback HTTP base URLs. The caller still supplies the
independent authenticated registry and DID readers; the helper does not
convert HTTP transport trust into a ledger anchor.

`buildDecisionEvidenceClaim` assembles the v1 issuer/verifier claim from a TR
evidence bundle, independently supplied accepted-epoch metadata, publication
signatures, a resolved DID method, exact scope, and governance event
references. It derives the policy snapshot and Merkle path from the bundle,
checks the accepted epoch identity/roots/validity, inclusion leaf, and policy
commitment, and rejects recognition or auditor records. The builder does not
authenticate the supplied accepted epoch, maintainer keys, DID observation,
or current decision point. The existing verifier remains mandatory before
using the result for VC authorization.

The VC integration adapter can now consume the optional API route through
`createVcSignerCandidateFromApi`. It uses the client verifier with independent
finalized registry and DID readers before converting the candidate into a VC
signer descriptor. It rejects an API response that omits the `client-required`
marker or whose evidence cannot be corroborated by the trusted readers. The
HTTP response itself is never a signer-authorization proof.

`issueVcSignerAuthorizationFromApi` carries that authenticated candidate into
the existing pinned-domain authority signer. It validates the returned proof
before publication, while the signer port still has to independently recheck
current finalized decision and governed authority-key state before using key
custody. The simulator journey verifies the proof against the pinned VC
authority and confirms a missing finalized registry decision does not invoke
the authority signer.

`createCompactLedgerDecisionReaders` projects a host-supplied finalized Compact
ledger view into the client reader interface. It matches registry and epoch
commitments to that ledger, including the sealed deployment-network commitment
and the publication's network commitment, selects the exact current issuer/verifier record
through its on-chain scope index, and reads current policy, status, lifecycle
event, and action sequence from the same view. It also checks the accepted
epoch's wall-clock interval against a host-supplied sequence-to-time mapping;
the simulator uses its fixed test mapping, while a live host must supply its
own authenticated projection. The authorization ID is a
lookup hint, not evidence of current membership. A newer unrelated epoch does
not invalidate an older epoch within its sequence window when the current
policy and exact grant are still unchanged. The host remains responsible for
proving the ledger view's network finality and currency, accepted-epoch block
and transaction references, historic maintainer set, off-ledger evaluation
time and its sequence-to-time projection, and DID-state observation. The
Compact ledger does not supply a wall clock. Passing a simulator ledger satisfies none of
those production provenance requirements.

The checkpointed reader composition reuses the deployment action reader's
block-hash-scoped Compact ledger read for current VC decisions. It checks the
checkpoint network and deployed address against the caller-selected decision
before asking a separate authenticated historical-publication port for the
epoch and signer context. That port receives the exact finalized block hash;
it must prove historical signer membership, not infer it from today's
maintainer map. This remains an integration boundary rather than a live
network finality or DID-state implementation.

`createVerifiedDecisionEvidenceSource` supplies the optional API route from an
indexed evidence bundle without treating that index as an anchor. It builds a
claim, requires exact role and authorization ID, obtains the expected
registry/scope selection and finalized readers from one separate trusted host
port, and runs the full client verifier before returning the claim. Indexed
candidate data cannot select its own registry, contract, DID, or scope.
The API still marks the response `client-required`; the consumer must verify
again using its own independently authenticated readers. In the simulator
demo, a stale issuer or verifier claim after suspension or revocation causes
the source to fail closed and the HTTP route to return 503. A live host must
replace both the bundle index and reader port with genuine finalized sources.

## Inputs

The candidate builder receives a versioned decision-evidence bundle and
explicit verifier configuration. The bundle contains:

- Registry DID, network identifier, registry contract address, format version,
  exact issuer or verifier grant, resource scope, policy ID and version, and
  lifecycle status at the decision sequence.
- An epoch ID, state/event/policy roots, publication sequence and validity
  window, the publication policy commitment and sequence window used in the
  Compact signing payload, the full threshold signer set, and the Merkle path
  for the grant. Timestamps are off-ledger projections, not signed sequences.
  The claimed decision sequence must be between publication and the inclusive
  epoch end sequence; this range check does not establish finality or currency.
  Grant and DID-state Merkle paths are limited to 256 siblings in this profile.
- The subject `did:midnight`, absolute verification-method reference, native
  public key, observed positive DID state version, required relationship, and
a DID state proof or authenticated ledger observation.
The v1 client verifies authenticated ledger observations only. A
`state-proof` claim is structurally representable but rejected by the client
until a DID-ledger-specific proof verifier is available; the generic Trust
Registry Merkle algorithm must not be presumed to prove DID state.
  For a ledger-observation claim, its transaction hash must also match the
  independently obtained observation; a block/version match alone is not enough.
  That observation must explicitly report a non-deactivated DID state.
- Governance event references for the grant transition, quorum, policy
  snapshot, and any supersession affecting the decision. Except for the
  publication event checked by the epoch verifier, these are unverified
  lookup hints until authenticated event evidence is supplied; consumers
  must not infer those transitions from the hashes alone.

Verifier configuration supplies an independently accepted registry contract
identity and network, an epoch root accepted from that contract or an
authenticated finality source, a trusted DID-state reader, a decision
sequence or trusted off-ledger evaluation instant, and the exact requested
resource. It must not be populated from the candidate bundle itself. Textual
DID key references and public keys carried by the bundle are claims until
matched against that DID state reader at the observed version.

## Verification order

1. Parse a strict versioned schema; reject unknown role, suite, status,
   malformed commitments, noncanonical identifiers, and absent proof fields.
2. Match the configured registry network and contract identity. Resolve the
   epoch from the independent anchor, not from bundle metadata, and compare
   all committed roots, sequences, policy commitment, and format version.
3. Verify the complete epoch publication quorum against the governed
   maintainer set and threshold effective at its publication sequence. The
   present single-signature bundle is insufficient when that threshold is
   greater than one; reject rather than assuming its first signature stands
   for the quorum.
4. Reconstruct the grant leaf and Merkle root, verify the policy snapshot and
   exact requested role/resource, and prove the grant is current for that
   scope at the selected decision point. A historical inclusion proof alone
   does not prove present authorization.
5. Resolve the DID at the anchored state version. Match controller, exact
   absolute method ID, native key bytes, method status, and role relationship.
   Issuers require `assertionMethod`; verifiers require `authentication` or
   `capabilityInvocation`. Reject a key that was removed or superseded before
   the selected decision point.
6. Evaluate policy effective interval, authorization lifecycle, and epoch
   freshness using one explicitly selected decision point. A Compact action
   sequence must never be interpreted as a wall-clock timestamp. Reject
   unfinalized or stale anchors and a policy superseded before that point.
7. Return a typed decision candidate with the authenticated method, key,
   DID version, scope, policy, decision sequence, and anchor references.
   Only #73 may map that candidate to the VC descriptor and sign the
   domain-bound authority proof.

## Lifecycle result

Only a current `active` grant for the exact scope yields a positive
candidate. `proposed` and `authorized` are pending, not active. `suspended`,
`revoked`, `superseded`, and `archived` fail closed for new VC decisions. A
historical proof of one of those states may be returned for audit, but must
not be relabeled as current. Missing current-scope evidence is
`not-authorized`; wrong resource is `out-of-scope`; malformed cryptographic
evidence is `invalid-evidence`. Keep those outcomes distinct in the query
layer.

Issuer status-registry identity and authority must derive from the verified
status-policy binding preimage, not optional bundle URLs. An issuer decision
evidence envelope carries the strict preimage and checks its registry ID,
authorization ID, and hash against the committed grant; verifier envelopes
must not carry issuer status policy. Artifact and deployment
references are discovery metadata unless their digests appear in verified
governance state. Applicant eligibility attestations are not post-approval
signer authorization evidence.

## Delivery slices and acceptance tests

1. Add a strict decision-evidence schema and JSON Schema export with issuer
   and verifier fixtures. Keep the current evidence bundle type intact until
   the additional anchor and DID fields are produced by the registry.
2. Export an independent epoch-anchor verifier that checks complete
   publication quorum and selected-time policy state. Do not accept the
   current caller-supplied public key as self-authenticating evidence.
3. Add a DID-state adapter using the published DID package, with positive
   native-key observations and negative substituted key, wrong controller,
   removed method, wrong relationship, stale version, and wrong network cases.
4. Build the typed candidate only after epoch, grant, policy, DID, and scope
   proofs pass. Test suspended party, withdrawn schema, wrong request profile,
   superseded grant, stale/unfinalized epoch, tampered Merkle path, and
   unpinned root.
5. Wire the candidate into #73's exact VC descriptor mapping and authority
   proof. Run `./run.sh --light`, fresh `./run.sh integration`, focused
   adversarial vectors, and independent final-head security review.

This is a no-bypass plan: until slices 1-4 are implemented, the client must
continue to describe its result as consistency with caller-authenticated
anchors, not as independent signer authorization.
