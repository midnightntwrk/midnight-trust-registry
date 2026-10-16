# Evidence, epochs, and time

Evidence tells a relying party **why** a scoped grant was valid, not just that a row appeared in an index.

## Application evidence

The applicant controls a Midnight DID and supplies a signed VC/VP to a trusted evidence-verifier service. The service challenges the applicant, verifies proof/status/policy, and signs a canonical redacted envelope binding registry, application, applicant, role, exact scope, policy, evaluation/expiry values, and a commitment to the verified signed status decision and governed issuer status policy. The private VP, claims, and status statement remain off-ledger. The status commitment is auditable only with the exact retained signed witness, independently authenticated governed binding, and historical DID state; it is not itself a public non-revocation proof. A one-use challenge closes the replay window. The [application-evidence protocol](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/spec/application-evidence.md) defines the canonical envelope.

## Decision evidence

The proposal binds the evidence-verifier key, policy version, nonce, application commitment, and maintainer signer set. An approval and activation create separate governance events. A portable bundle links the record and event to an epoch root. Historical bundles must be retained in `evidenceArchive` before a later lifecycle change; the API returns `424` rather than attaching a later epoch to an earlier decision when that archive is missing.

An external caller must verify the bundle against an **independently trusted** registry/epoch anchor, not simply trust JSON returned by the same API. Check the exact role and scope, current lifecycle, policy commitment, signer threshold, event/inclusion proof, and observation view. Client helpers support this evaluation, but the caller owns anchor selection.

The client package exports `verifyHistoricalAuthorizationEvidenceFromApi` and
`verifyHistoricalRecognitionEvidenceFromApi`. Pass the exact query selection
and an epoch record, publication key, and registry commitment authenticated
from ledger history. These functions fetch the native timestamped evidence
route and return only after its response, scope, signature, roots, and inclusion
proof verify. They do **not** authenticate the supplied anchor or decide which
epoch was canonical at that time. A `404`/`424` is an error, not an
authorization denial; remote HTTP is rejected in favor of HTTPS.

The integration package's `resolveCompactHistoricalEpochAnchor` can extract
that verifier context from a **host-authenticated finalized Compact ledger
view**. It checks the registry, accepted epoch record, committed policy
version, and publication signer before the client evaluates the HTTP claim.
The embedding host still must authenticate the deployment and finalized
ledger view, select the appropriate historical epoch, and supply a trusted
counter-to-time mapping. Midnight counters are not network timestamps.
In the local demos, the expected per-statement epoch is derived from the
Compact status sequence before the API response is verified; the HTTP server
does not choose its own anchor. This fixture-specific selection does not
establish canonical network history for a production deployment.

The TRQP adapter also exports issuer/verifier and recognition evidence
verifiers. They require explicit request time, a trusted authority DID, and a
caller-supplied epoch anchor; they reject a response whose tuple, proof, or
allow/deny result disagrees with the request and proved lifecycle. Recognition
requires the exact external registry and scope context and does not authorize
local issuance. Fetch-and-verify helpers reject non-loopback HTTP, redirects,
and unavailable evidence instead of turning them into negative decisions. The
signed issuer/verifier and governed recognition demos call the live TRQP
evidence routes through these helpers and verify against simulator-ledger
anchors, including archived decisions after later lifecycle changes.

## Current VC trust decisions

The API's issuer/verifier decision-evidence response is a `client-required`
claim, not an authorization. A VC consumer selects its expected registry,
deployment, subject DID, role, and exact scope independently. It then calls
`verifyDecisionEvidenceWithTrustedReaders` with readers that authenticate the
current finalized registry and DID states. The integration package's
`createCompactLedgerDecisionReaders` projects a supplied Compact ledger view:
it matches the sealed registry and deployment-network commitments, accepted
epoch roots and sequence window, publication context, current policy, and the
exact current authorization record and status in its scope index. It also
compares the epoch's off-ledger dates to a host-supplied sequence-to-time
projection. The authorization ID in the response is only a lookup hint.

The host must establish network finality and currency, authenticate the
historical publication maintainer set and DID observation, and provide the
time projection. The Compact ledger has no wall clock. A simulator ledger or
the API response alone cannot satisfy these provenance requirements; a
missing or inconsistent read fails closed before any VC signer descriptor is
accepted.

## What an epoch means

An epoch is a committed bounded registry view. It is not a date or time returned by the Midnight network. Compact counters and event hashes establish order. An operator may attach observation timestamps off-chain; those timestamps require their own trust and finality assumptions. Historical `at` queries select evidence for a requested evaluation instant, but a stale/unfinalized or missing epoch fails closed. See the [time and evidence specification](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/spec/trqp-time-and-evidence.md).

## Current versus historical

An active proof at issuance time can support the statement “issuer was authorized then.” It cannot by itself say “issuer may issue now.” For a credential, verify the VC signature and status separately and apply current policy restrictions. A revocation's effect on already issued credentials is a policy decision, not inferred from the registry status alone.
