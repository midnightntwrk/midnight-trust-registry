# Trust Registry Integration

Integration scenarios for `midnight-trust-registry`.

Current coverage:

- local simulator trust-decision flows for issuer, verifier, and recognition
- `prepareIssuerProposalAction`/`executeIssuerProposalWithSignatures` and
  `prepareIssuerDecisionAction`/`executeIssuerDecisionWithSignatures` expose
  policy-bound Compact digest inputs and accept explicit maintainer signatures.
  Proposal also requires a separate evidence-verifier signature. The focused
  integration test uses two distinct non-bootstrap maintainers under a 2-of-3
  policy and rejects insufficient, duplicate, stale, wrong-policy, and
  wrong-evidence-verifier bundles. The API's optional governed-action port can
  submit external approval/activation signatures to this simulator path;
  proposal and production network submission still need a deployable adapter.
  Fixture-driven issuer helpers still sign internally.
  Run `pnpm --filter @midnight-ntwrk/trust-registry-integration exec vitest run
  src/test/external-issuer-signers.integration.test.ts` to reproduce it.
- `prepareVerifierProposalAction`/`executeVerifierProposalWithSignatures` and
  `prepareVerifierDecisionAction`/`executeVerifierDecisionWithSignatures` expose
  the exact request-profile proposal and lifecycle digests to external
  maintainers. The simulator test requires two distinct active signatures at
  every transition and rejects wrong scope, unknown or duplicate signer,
  policy substitution, and stale signatures without advancing governance.
  It checks the resulting active verifier evidence bundle independently. This
  is not yet a public verifier application or HTTP action route.
- Auditor proposal and decision actions have the same explicit 2-of-3 signing
  boundary, but retain an auditor-only mandate scope and request-profile ID.
  The focused test rejects substituted mandates, duplicate/unknown signers,
  policy substitution, and stale lifecycle signatures, then independently
  verifies the active auditor bundle. It does not authorize blanket access to
  holder presentations or make an auditor grant interchangeable with a
  verifier grant.
- External-authority recognition exposes caller-signed proposal and decision
  digests with the recognized authority DID, external registry, and exact
  resource scope bound into the Compact action. The 2-of-3 simulator test
  rejects insufficient, duplicate, substituted-authority, wrong-policy, and
  stale bundles, then verifies the active recognition evidence. Recognition
  is not a local issuer, verifier, auditor, or maintainer membership grant;
  the demo evidence hash is a fixture, not third-party accreditation proof.
- Maintainer onboarding exposes prepared proposal, approval, and activation
  digests and accepts signatures from existing maintainers at each transition.
  The 2-of-3 simulator test rejects insufficient, duplicate, candidate
  self-voting, wrong-policy, and stale signatures without advancing governance,
  then confirms the activated candidate can co-sign a later issuer action.
  Fixture helpers still sign internally; production signing and network
  submission are not provided by this simulator harness.
- anchored epoch evidence validation
- DID-backed resolution of trusted `did:midnight` subjects through official
  `midnight-did` helpers
- VC-backed issuer-descriptor construction using the published
  `@midnight-ntwrk/credential-compact` and
  `@midnight-ntwrk/credential-did-midnight` packages after TR bundle and DID
  method verification. This is a candidate descriptor, not a live
  cross-contract trust anchor. The bundle's `referencedStatusRegistryId` is
  metadata outside the signed authorization leaf and must not be treated as
  authenticated status-policy evidence. Policy-to-VC scope mapping, anchored
  status policy, and live revocation checks remain separate work.
- a clean-checkout Compact composition probe that imports the published
  `credential-compact` module through its npm export, derives VC and VP body
  roots, accepts matching envelope linkage, and rejects mismatched schema,
  claim roots, or issuer methods. The upstream generic relation deliberately
  does not compare holder bindings; the application evidence profile must check
  them separately. The probe tests claim-root, issuer-method, and schema links,
  but does not assert that the generic relation accepts a holder mismatch.
  Run it with `pnpm run test:light` in this package. This is a
  compiler/runtime compatibility and typed-envelope test, not a proof of
  applicant eligibility, issuer authorization, or live credential status.
- a fixture-backed application VP verifier port using published VC 0.2.0
  proof circuits and DID resolution. It verifies issuer/holder method binding,
  issuance and presentation signatures, nonce, holder binding, proof time,
  and status-reference structure, then calls explicit trusted adapters for
  credential-body binding, issuer authorization, live status, and role claims.
  The scenario fixture serializes both proofs into canonical JSON and derives
  body roots from the submitted credential and presentation body strings;
  changing either submitted body or a proof signature fails verification.
  The fixture's role scope, expiry, holder, status registry, handle, and
  authority method are read from
  the signed credential body, and its claims callback uses that observed scope
  for issuer, verifier, auditor, and maintainer applications. Issuer eligibility
  and live status are still fixture-controlled answers, not production trust
  or revocation determinations. The test-family status decision must match the
  signed registry, handle, and authority method and be active and fresh; tests
  reject revoked, mismatched, and stale decisions. No authenticated external
  status witness is verified here.
  The body-binding adapter is responsible for establishing that the holder,
  status, expiry, and role claims came from the signed credential body root;
  the published generic proof circuits alone do not establish that relation.
  No production credential-family adapter is provided in this slice, so this
  fixture-backed port must not be exposed as a public eligibility verifier.
  The role-claims adapter is not passed the requested scope and
  must return the scope commitment derived from claims bound to the verified
  credential body root; echoing the requested scope is not sufficient. The
  port rejects a different attested scope. It allows 60 seconds of future
  proof-clock skew, accepts presentations at most five minutes old, and caps
  evidence validity at the earliest of credential expiry, status validity,
  and 24 hours. The port returns only
  redacted commitment-sized results. It is not a public intake route or a
  standalone non-revocation verifier; callers must supply trustworthy family
  body roots and all four family assertions. Retryable DID/status dependency
  outages produce a redacted `unavailable` result rather than an eligibility
  denial; adapters must signal their own infrastructure outages explicitly.
  Run its focused tests with
  `pnpm --filter @midnight-ntwrk/trust-registry-integration exec vitest run src/test/application-vp-verifier.integration.test.ts`.
- `createApplicationVpIntakePorts` supplies the existing API one-use intake
  with published VC/VP verification and DID-bound signing/verification
  callbacks. It matches the configured signer key to its Midnight DID
  assertion method and rejects an invalid signature. The API intake still
  owns challenge consumption, authorized-verifier lookup, canonical envelope
  construction, and proposal submission. The family adapter must authenticate
  credential claims and status; these ports do not make the resolver trusted,
  establish governed key membership, or create a public route.

The repository pins the compiler in `.compact-version` and Nix, and pins the
runtime in `contracts/trust-registry/package.json`. The probe
resolves the npm-exported `composable.compact` directory as a compiler include
path; no VC source or generated output is vendored into this repository. Its
generated module uses the probe package's dev dependency on Compact runtime;
direct consumers pin that runtime exactly. The installed identity runtime gate
checks published DID/VC package requirements and their resolved runtime before
running the probe.
