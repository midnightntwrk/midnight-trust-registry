# 0.1.0 Acceptance Evidence Map

Status: local working index, not an issue-closure or release approval record.

The open [0.1.0 issues](https://github.com/midnightntwrk/midnight-trust-registry/milestone/1)
must be reconciled against code and exact-head validation before closure.
The files below identify where to check behavior; their existence alone does
not prove every acceptance criterion. In particular, a simulator test is not
a finalized-network read, and a package smoke is not a live status proof.

| Issues | Current executable evidence | Still required before closure |
| --- | --- | --- |
| #39 historical API/TRQP | `packages/trust-registry-api/src/test/trust-registry-api.test.ts`; `adapters/trqp/src/test/trqp-adapter.test.ts`; timestamped actor queries in `scripts/demo-signed-membership-journey.mjs` | Audit every requested timestamp/problem/extension case against the issue and record the merged implementation PR. |
| #58, #59, #78 actor journeys | `scripts/demo-governed-registry.mjs`; `scripts/demo-signed-membership-journey.mjs` for issuer, verifier, auditor, maintainer; `pnpm run packed-artifacts:smoke -- --actor-journey` installs the ten tarballs in a temporary consumer | Pass full integration and packaged actor smoke at a clean candidate SHA; confirm the scrubbed report and all issue-specific negatives. |
| #60 adversarial matrix | The governed demo emits invariant, boundary, expected, and observed categories; Compact/API/client/TRQP tests cover additional failures | Audit the issue's full case list and preserve a reproducible report from the candidate run. |
| #67, #75, #76 evidence and policy | `contracts/trust-registry/src/test/trust-registry.test.ts`; `packages/trust-registry-integration/src/test/application-status-attestation.integration.test.ts`; `packages/trust-registry-api/src/test/signed-mutation-http.test.ts` | Match role-specific VC/VP, policy-rotation, evidence-verifier, and privacy criteria to exact tests; pass full integration. |
| #77 signed mutation | `packages/trust-registry-api/src/test/signed-mutation-http.test.ts`; `packages/trust-registry-api/src/test/mutation-intent-preflight.test.ts`; four packed actor journeys | Confirm restart, conflict, and all unauthenticated-write denials at the candidate revision. |
| #79, #73 VC anchor and Ledger 8 consumer | `packages/trust-registry-integration/src/test/decision-evidence-simulator.integration.test.ts`; `packages/trust-registry-integration/src/test/vc-authorization.integration.test.ts`; compiled `vc-authority-consumer.compact` fixture | Finish the exact issue-vector audit. The integration tarball currently packs `dist/**` but not its TR-owned Compact consumer fixture, so a tarball-only Ledger 8 consumer check is not yet proven. Distinguish local compiled consumption from deployed synchronous cross-contract calls; host-authenticated finalized registry/DID readers remain deployment dependencies. |
| #201, #202 signer and nonce rules | `contracts/trust-registry/src/test/trust-registry.test.ts` checks ordered signer slots; `packages/trust-registry-api/src/test/signed-mutation-state.test.ts` checks bounded nonce retention | Record exact permutation/padding and restart/capacity evidence, then link the signed implementation commits after merge. |
| #90 issuer status policy | The issuer status binding and application status-attestation tests verify a governed commitment and reject substitution | A consumable published status-authority package or approved adapter is still missing; no live non-revocation or federation status claim may be inferred from fixture evidence. |
| #200 public deployment | Constructor, deployment-domain, replay, and provider-adapter tests exist; network and genesis are configurable | A funded operator, approved network pin, adversarial supported-target deployment, independently finalized readback, and incident/recovery decision are still missing. Do not merge the promotion PR as public-network ready. |
| #45 release | Signed-source manifest generator, package hash verifier, ten packed artifacts, four packaged actor journeys, and draft [candidate note](../guide/release-candidate-0.1.0.md) | Full integration and artifact checks at the candidate revision, manifest-backed clean consumer smoke, exact-head CI/review, release owner, and recovery approval are pending. |
| #178 milestone protection policy | The [delivery harness](milestone-0.1.0-delivery-harness.md) requires green exact-head CI and current-head LLM review; the user explicitly declined a milestone branch-protection rule | Reconcile the stale issue with that policy decision; do not treat absence of branch protection as a release blocker or relax develop/main protections. |

## Next Local Qualification Sequence

1. Let the active full integration run finish; diagnose a failure without
   discarding its generated proof artifacts. The previous run failed after
   key generation because the VC demo omitted the simulator sequence clock;
   the fast light gate now exercises that path.
2. On a clean signed/DCO candidate tree, run the full package-content check,
   repack, generate the manifest, and run the manifest-backed four-role
   packed actor smoke. Record the source SHA and timings separately from
   manifest bytes.
3. Audit each open issue's remaining checkboxes against the exact test result.
   Close only after a merged PR is linked with its merge SHA, validation
   commands, and deliberately deferred criteria. Leave #90, #200, and #45
   open while their real release dependencies remain.
