# Trust Registry Integration

Integration scenarios for `midnight-trust-registry`.

Current coverage:

- local simulator trust-decision flows for issuer, verifier, and recognition
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
  issuer authorization, live status, and role claims. The role-claims adapter
  must return the scope commitment derived from claims bound to the verified
  credential body root; echoing the requested scope is not sufficient. The
  port rejects a different attested scope. It allows 60 seconds of future
  proof-clock skew, accepts presentations at most five minutes old, and caps
  evidence validity at the earliest of credential expiry, status validity,
  and 24 hours. The port returns only
  redacted commitment-sized results. It is not a public intake route or a
  standalone non-revocation verifier; callers must supply trustworthy family
  body roots and the three eligibility adapters. Run its focused tests with
  `pnpm --filter @midnight-ntwrk/trust-registry-integration exec vitest run src/test/application-vp-verifier.integration.test.ts`.

The published VC Compact package targets Compact 0.31.1 and runtime 0.16.0.
The repository pins that compiler in `.compact-version` and Nix. The probe
resolves the npm-exported `composable.compact` directory as a compiler include
path; no VC source or generated output is vendored into this repository. Its
generated module uses the probe package's dev dependency on Compact runtime;
direct consumers pin runtime 0.16.0 exactly, and the light gate checks that
published DID/VC package requirements match before running the probe.
