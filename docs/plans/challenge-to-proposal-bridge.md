# Challenge-To-Proposal Bridge

Status: implementation plan for #127, stacked on #126. This is not a claim
that challenge-backed proposal intake is implemented.

## Boundary

The challenge service in `packages/trust-registry-api` commits the canonical
`tr-scope-v1` object. The simulator currently puts a resource-ID hash in the
application envelope's `scopeCommitment` and uses a deterministic challenge
hash. Neither value can be substituted for the challenge service's values.
The governed resource ID and the canonical scope commitment are separate
inputs and must remain separately checked.

`api -> cli -> integration` is an existing package dependency path. Importing
the API challenge service into integration would introduce a cycle. Put the
shared intake protocol and scope/resource consistency checks below both API
and integration, leaving random challenge storage and operational controls in
API. The simulator can exercise the same protocol through an injected
one-use challenge consumer without importing API. An API-level test must
exercise the real store and consumer implementation.

## Ordered Flow

1. Parse one versioned role-specific `AuthorizationScope` and derive its
   commitment with `computeAuthorizationScopeCommitment`. Validate that the
   scope names the separately governed resource: issuer resource type and ID,
   verifier/auditor request profile, or maintainer registry. Do not infer a
   full scope from a resource-ID hash.
2. Issue a challenge bound to registry, application, subject DID, evidence
   verifier DID, role, policy ID/version, and that canonical commitment.
3. Verify the VP against the exact nonce and applicant DID before consuming
   the challenge. Keep the raw VP and nonce out of the ledger, journal, and
   public evidence bundle.
4. Atomically consume the challenge once. Use only the returned canonical
   challenge hash, not an envelope-supplied value, in the evidence verifier's
   signed envelope. A failed signature or proposal may spend a challenge;
   it must never make the same challenge reusable.
5. At proposal intake, verify the evidence signature, consumed hash,
   canonical scope commitment, role, subject DID, policy version, and
   separate governed resource. Store only the evidence commitment in the
   contract action and retain private evidence off-ledger.

## Validation Matrix

- Positive issuer, verifier, auditor, and non-bootstrap maintainer proposals
  use one challenge and one canonical scope each.
- Reject scope substitution, role or DID mismatch, resource mismatch, nonce
  replay, expiry, and case-variant ambiguity without consuming a valid
  challenge on a failed binding check.
- Reject an evidence envelope that uses the old resource-ID stand-in even
  when its signer recomputes the envelope commitment.
- Check that no raw VP or nonce enters ledger, journal, report, or evidence
  bundle fixtures. Run focused tests, `./run.sh --light`, and full integration
  before publication.
