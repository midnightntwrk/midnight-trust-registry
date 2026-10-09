# Challenge-Bound Application Evidence Time (#143)

Status: local design checkpoint; not an implementation or merge claim.

## Trust Boundary

The VP verifier supplies `verifiedAt` and `expiresAt`, but these values are
claims to validate, not challenge-clock authority. The challenge store is the
authority for `issuedAtMs` and `expiresAtMs`. The reference API's injected
evaluation clock is trusted by the operator, not by the applicant or VP. The
contract has no datetime primitive; these are off-ledger intake and evidence
validation rules, followed by a ledger commitment to the accepted evidence.

## Reference Profile

- A challenge is live in the half-open interval `[issuedAtMs, expiresAtMs)`;
  the current maximum issuance window remains five minutes.
- The reference profile permits zero skew at the intake seam. Verification
  must occur at or after issuance, before challenge expiry, and no later than
  the trusted intake evaluation instant. A deployment that needs clock skew
  must specify and test an explicit policy value; it must not infer a tolerance
  from attacker-supplied timestamps.
- Signed evidence expires after `verifiedAt` and no more than 24 hours after
  it. The evidence expiry need not equal the five-minute challenge expiry:
  the nonce proves freshness of the VP, while a later approval may use the
  signed evidence within its policy window.
- The trusted evaluation instant must itself be within the live challenge
  window. A backward clock jump before issuance is an operational error, not
  an opportunity to mint backdated evidence.
- Every pre-consume time or binding rejection leaves the challenge live.
  Atomic consume remains the replay boundary; two concurrent valid requests
  must not both propose an application.

## Implementation Order

1. Persist `issuedAtMs` beside `expiresAtMs` in the challenge record and
   validate the pair on insertion. Expose a non-consuming store read that
   returns the stored window only after matching the challenge and complete
   binding. Do not trust the issuance response supplied back by a caller.
2. Have `ApplicationChallengeService` return the stored window to intake while
   retaining atomic check-and-delete for consume. Keep a cheap live preflight;
   its result is advisory and must not be treated as a reservation.
3. After VP verification and before consume, parse timestamps strictly and
   enforce the reference profile against the stored window and trusted
   evaluation instant. Never sign or propose an envelope from an invalid
   window. The existing envelope `verifiedAt < expiresAt` validation remains.
4. Update the application-evidence specification and API boundary docs, then
   test exact issue/expiry/lifetime limits, backdated and future verification,
   overlong evidence, clock rollback, failure without nonce consumption, and
   concurrent consume. Run focused API integration, `./run.sh --light`, and
   `pnpm audit --audit-level low` before a signed/DCO commit and publication.

This slice stacks on #129. It does not supply a durable public challenge store,
authenticated applicant route, or on-ledger wall-clock semantics.
