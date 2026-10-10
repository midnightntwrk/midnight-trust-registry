# VC/VP Eligibility Attestation For 0.1.0

Status: local partial implementation for #76, stacked after the #127
challenge-to-proposal bridge. The published-package proof/DID port and
issuer-fixture adversarial tests and a typed #127 intake callback adapter exist.
The API integration suite now exercises that adapter through the one-use
challenge service with published VC proof fixtures, DID-bound signing, and
redacted proposal evidence. The policy/status assertions in this fixture are
test-only; four-role fixtures, production family/status adapters, durable
challenge storage, and a public route remain open.

## Published Package Boundary

Use `@midnight-ntwrk/credential-compact@0.2.0` for the family-neutral
Compact proof types and pure verification circuits,
`@midnight-ntwrk/credential-did-midnight@0.2.0` for Midnight DID method
binding, and `@midnight-ntwrk/midnight-did@0.7.0` for DID resolution. Do not
import source, generated output, or private packages from the VC repository.
The oracle VC protocol agent and status-registry packages are currently
private; their APIs are not an npm dependency of this registry.

The registry verifies an *application eligibility decision*, not the VC
family's undisclosed claims. A family adapter supplies the credential and
presentation body roots, typed claim checks, and trusted status observation.
The generic Compact proof circuits verify the proof contexts and signatures;
the DID adapter binds signer method references to resolved Midnight DID keys.
The registry then applies its role policy and produces only commitment-sized
evidence for governance. A callback that merely returns `verified: true` is
not a production verifier.

## Verification Order

1. Parse a bounded, versioned submission. Never journal raw credential,
   presentation, holder DID, or private witness fields.
2. Resolve the applicant's Midnight DID authentication method and the VC
   issuer's assertion method from the trusted DID resolver. Fail closed on
   deactivation, missing relationships, key mismatch, or ambiguous method IDs.
3. Verify the credential issuance and VP presentation context proofs against
   family-provided body roots, the exact one-use challenge hash, and explicit
   holder binding. Do not infer a body root from untrusted text.
4. Evaluate issuer authorization from an independently anchored registry
   snapshot and evaluate status against an independently trusted VC status
   source. A status-reference shape check is not a non-revocation proof.
5. Apply role-specific claims and the live canonical `tr-scope-v1` binding
   supplied by intake, not a scope captured when the verifier was constructed.
   Reject stale credential or proof time against each call's trusted evaluation
   time; the Compact registry contract does not supply wall-clock time.
6. Return only subject DID, nonce, evaluated scope commitment, presentation
   hash, claims commitment, and validity timestamps to the #127 intake seam.
   Intake rejects a scope-commitment mismatch before challenge consumption.
   Sign its canonical evidence
   commitment with the evidence verifier's DID assertion key. Never return a
   raw VP from the public surface.

## Delivery Slices

- Define a strict verifier port and typed rejection categories in the
  integration package, with package-local test fixtures and no public route.
- Implement DID method and Compact context-proof checks using the published
  packages; require injected family body-root and status/claims adapters.
- Add positive issuer, verifier, auditor, and maintainer fixtures and
  adversarial challenge, subject, issuer, scope, status, expiry, and claim
  cases. The issuer proof fixture now reaches #127's one-use intake callback;
  connecting this path to a Compact simulator proposal remains open.
- Only then add an authenticated API route with bounded payloads, a durable
  atomic challenge store, rate limits, redacted errors, and retention policy.

## Exit Criteria

`./run.sh --light` and `./run.sh integration` pass. A valid fixture VP
produces a real JubJub-signed evidence commitment that the simulator
proposal checks; invalid evidence never reaches proposal. Tests confirm raw
VC/VP data and the nonce are absent from journal, ledger, public bundle, and
report. Production status verification and a public route remain explicitly
blocked until their trusted adapters are implemented and reviewed.
