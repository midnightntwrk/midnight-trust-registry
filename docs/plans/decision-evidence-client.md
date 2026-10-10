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

The v1 profile supports `did:midnight` and the published DID package's native
SchnorrJubjub method. Opaque JWK methods are not silently converted to a
JubJub point. Other suites require a separately specified verification path.

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
- The subject `did:midnight`, absolute verification-method reference, native
  public key, observed positive DID state version, required relationship, and
  a DID state proof or authenticated ledger observation.
- Governance event references for the grant transition, quorum, policy
  snapshot, and any supersession affecting the decision.

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
status-policy binding, not optional bundle URLs. Artifact and deployment
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
