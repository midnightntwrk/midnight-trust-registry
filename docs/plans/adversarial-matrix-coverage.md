# Adversarial Matrix Coverage

Issue [#60](https://github.com/midnightntwrk/midnight-trust-registry/issues/60)
tracks an end-to-end rejection matrix. This table distinguishes the checked
`adversarialMatrix.cases` report from ordinary unit tests and from unrecorded
demo assertions. `Observed` means the demo asserts a real rejection and records
the case; it does not imply production-network proving or finality.

| Requirement | Current evidence | Gap |
| --- | --- | --- |
| Self-approval | `maintainer-approve-candidate-self-vote`, `maintainer-activate-candidate-self-vote` reject the candidate key through the API; `trust-registry.test.ts` separately passes an active target maintainer's valid signature as a co-signer and observes Compact's `own DID` rejection without advancing governance state | The public candidate route may reject earlier at active-signer lookup; do not present that API response as the proof of Compact's self-DID exclusion. |
| Duplicate signer | `client-issuer-duplicate-signer`, role-specific `*-proposal-duplicate-signer` and `client-*-proposal-duplicate-signer` cases for issuer, verifier, auditor, and maintainer, plus role-specific `duplicate-signer` API action cases. These bundle-builder cases leave governance state unchanged. `trust-registry.test.ts` separately submits equal signer IDs directly to Compact and checks the strict-order rejection without state change | These four membership proposal roles are covered; recognition is a separate governed-resource path. Do not attribute the client-side matrix rejections to Compact. |
| Insufficient quorum | `compact-issuer-insufficient-quorum`, role-specific API action and `*-proposal-insufficient-quorum` cases, and direct `compact-*-proposal-insufficient-quorum` cases for all four membership roles; `compact-old-policy-signature-replay` and `compact-{verifier,auditor,maintainer}-old-policy-signature-replay` reject former-policy signatures after threshold revision; `compact-recognition-{proposal,approval}-old-policy-signature-replay` rejects old-policy signatures for current recognition actions and accepts correctly signed replacements; `policy-revision-one-signer` and `new-policy-registration-two-signers` exercise the two policy phases over HTTP; role-specific `*-revised-policy-insufficient-quorum` and `*-current-policy-after-threshold-change` cases cover revised-quorum rejection and activation | Old-policy replay is not yet exercised for every lifecycle action. |
| Key substitution | `compact-issuer-unknown-signer`, `compact-removed-maintainer-signer`, and `issuer-vp-holder-method-substitution` reject unknown governance keys and a post-signing VP method-reference change; `recognition-intake-rotated-authority-did-key` rejects an assertion signed before the resolved authority DID key changes | The recognition assertion covers a real resolved-key change, but not holder or maintainer DID rotation. A changed proof method reference is not the same as a changed resolved DID key. |
| Maintainer removal threshold | `compact-self-voted-maintainer-suspension`, `compact-self-voted-maintainer-revocation`, and `compact-removal-below-maintainer-threshold` | Self-votes are rejected; a separate non-conflicted signer cannot remove a maintainer when that would leave fewer active maintainers than the live threshold. The one-maintainer case cannot supply a non-conflicted signer. |
| Altered evidence commitment | `issuer-altered-evidence-commitment-api`, `issuer-altered-evidence-commitment-integration-preflight`, `compact-issuer-altered-evidence-hash`, and role-specific `compact-*-proposal-altered-evidence-hash` cases for issuer, verifier, auditor, and maintainer. Each proposal case changes the Compact evidence hash, re-signs it with the authorized evidence-verifier key, retains the old maintainer signatures, and checks that governance state does not advance | The four membership proposal roles are covered at this boundary. Recognition accreditation uses a separate authority-proof path; do not infer its coverage from these cases. |
| Altered policy ID/version | `issuer-signed-wrong-policy-id`, role-specific `*-uncommitted-policy-version` client cases for issuer, verifier, auditor, and recognition, `integration-old-policy-application-preflight`, `compact-old-policy-signature-replay`, and `policy-revision-stale-replay` over HTTP | All four bundle policy versions are checked at the client boundary; this is not proof of a deployed-ledger rejection or complete event history. |
| Expired evidence and unauthorized evidence verifier | `issuer-expired-signed-application-evidence`, role-specific `*-expired-evidence-api-preflight` and `*-expired-accepted-evidence-api` for issuer, verifier, auditor, and maintainer proposals; `issuer-unauthorized-evidence-verifier-api`, `issuer-unauthorized-evidence-verifier-compact` | Add a submitted Compact action with expired evidence; epoch expiry is separately checked by `issuer-expired-epoch`. |
| Issuer/verifier scope mismatch | `issuer-wrong-credential-family`, `verifier-wrong-request-profile`, `issuer-wrong-resource-api`, `verifier-wrong-resource-api`; issuer signed VP scope case. `compact-{issuer,verifier,auditor}-proposal-scope-substitution` re-signs altered verifier evidence but retains the original maintainer quorum, proving the changed Compact proposal payload is rejected while fresh signatures would execute | Recognition proposal scope substitution is separately checked; these simulator checks are not a submitted network transaction. |
| Stale epoch and tampered Merkle path | `issuer-expired-epoch`, `issuer-tampered-merkle-path`, `issuer-historical-proof-tampered-after-policy-revision`, `issuer-historical-epoch-signature-tampered`; issuer historical API/TRQP decision parity after suspension and revocation | Add a separately anchored public-query proof freshness case. |
| External recognition as authorization | `recognition-not-issuer-authorization`, `recognition-wrong-external-registry-api`, `trqp-wrong-recognized-registry`; `compact-recognition-external-registry-substitution` and `compact-recognition-resource-substitution` reject reuse of a valid signed proposal under a changed Compact input. Six `recognition-intake-*` cases reject registry/signature/policy/status/VP/key substitution in composed challenge and accreditation verification, then accept the valid fixture without consuming the challenge on failure | The accreditation anchor, status, and DID state are local fixtures; independent external accreditation and public-network finality remain unproven. |
| Historical state after suspension/revocation | Role-specific `historical-after-suspension` and `historical-after-revocation` client cases verify issuer, verifier, auditor, and recognition evidence; `*-historical-api-after-*` cases check public lookups at the same instants; issuer, verifier, and recognition `*-trqp` cases check decision parity | Auditor TRQP is not mapped by the adapter; define the protocol action before adding parity. |
| Historical state after threshold change | Issuer and verifier cases retain pre-revision bundles and query their original epochs after a Compact-backed threshold revision. `auditor-history-survives-threshold-change` and `auditor-historical-api-after-threshold-change` cover the defined auditor client/API paths. `recognition-history-survives-threshold-change`, `recognition-historical-api-after-threshold-change`, and `recognition-historical-trqp-after-threshold-change` cover recognition client/API/TRQP paths. All retain pre-revision active evidence through a subsequent revocation. | These are simulator-snapshot and Compact-backed harness tests, not deployed local-ledger readback. TRQP defines no auditor action, so no auditor adapter case is claimed. |

The report has API, Compact simulator, integration preflight, client, and TRQP
adapter entries. The
same invariant is **not yet** exercised at every relevant boundary, so issue
#60 remains open. Compact simulator failures are not proof of a submitted
Midnight transaction; the fixture uses deterministic local time and finality.

`pnpm run adversarial:report` runs the isolated Node test cases and writes a
`tr-adversarial-case-report-v1` JSON object to stdout. Its sorted case results
include a stable pass/fail reason code; a failing case does not stop later
cases. The command exits nonzero on a failed case or a count other than 198.
An interrupted, signaled, or abnormal test-runner exit is rejected even if a
partial TAP stream contains failed cases; it is not a complete case report.
Each TAP block may contain at most one top-level outcome, and it must name
the same stable case ID as its subtest header; duplicate or mismatched results
cannot be attributed as a pass or failure. This
checks report identity, not the authenticity of deployed-ledger evidence.
On a clean committed checkout, `node scripts/adversarial-case-report.mjs --archive`
also writes the full report once to a mode-0600 file under private ignored
`artifacts/adversarial-reports/`, named for the current source commit. It
prints the archive path, SHA-256, source revision, and pass/fail summary;
it refuses to overwrite an earlier run for that commit. The v2 archive also
requires exact case-ID parity with the governed demo and preserves its
invariant, boundary, expected, and observed categories beside the isolated
outcomes. These are two distinct test sources; the demo metadata is not an
assertion that every isolated case exercised every boundary. The archive is
test evidence, not a deployed-ledger or release-qualification result.
`pnpm run check:adversarial-parity -- --require-full` additionally compares
those isolated case IDs with the governed demo's machine-readable matrix.
It runs the independent case suite before the sequential demo. If the demo
aborts, the parity command exits nonzero but still emits the complete isolated
per-case outcomes and reasons, with unknown demo and missing-case counts shown
as `null` rather than a false zero. If the demo emits a failed matrix before
exiting, the failure report retains both matrices for diagnosis. A successful
parity report remains compact and requires 198 matching IDs.
The demo remains useful as one sequential actor journey, but its independent
case report is the regression gate when an earlier journey step fails.
The issuer, recognition, verifier, auditor, and maintainer former-policy
signature replay scenarios now live in `scripts/governed-demo-policy-replay.mjs`.
Each keeps the exact payload and action sequence fixed across the rejected
old-policy signature and successful current-policy control. Their isolated
counterparts remain in
`scripts/adversarial-compact.test.mjs`; the surrounding historical demo and
other inline scenarios still need extraction under #216. Neither lane is a
deployed-ledger replay test.
The same module also owns the post-revision historical client checks: retained
issuer, verifier, auditor, and recognition evidence, uncommitted policy
substitutions, superseded current-time use, and tampered Merkle and epoch
signatures. The historical HTTP/TRQP checks now run through
`scripts/governed-demo-historical-http.mjs`, which owns a separate loopback
listener for the archived policy snapshot and closes it before the later
mutable actor demo begins. These remain fixture API/adapter checks, not a
deployed local-ledger readback.
`scripts/policy-replay-isolation.test.mjs` separately proves that snapshot
publication advances its own simulator action count, while old-policy
signatures are rejected and current-policy signatures succeed for the exact
same prepared payload and sequence on a different harness. It runs in the
demo-smoke lane but is not a 199th adversarial matrix case.

The threshold-revision, evidence-verifier registration, and atomic maintainer
recovery journey now runs in `scripts/governed-demo-policy-recovery.mjs` with
its original six adversarial case IDs and positive receipt controls. The
independent counterparts are five named cases in
`scripts/adversarial-policy-api.test.mjs` and the Compact headroom case in
`scripts/adversarial-compact.test.mjs`. The governed demo remains sequential;
`check:adversarial-parity -- --require-full` verifies 198/198 case-ID parity
after this extraction. These tests remain simulator and fixture evidence, not
deployed local-ledger recovery or an independent finality check.
The public issuer/verifier resource and external-recognition registry lookup
rejections now run through `scripts/governed-demo-public-lookup-safety.mjs`.
Their independent named cases remain in `scripts/adversarial-api.test.mjs`
and `scripts/adversarial-recognition.test.mjs`; the extraction changes no
public API or deployed-ledger claim.
The issuer suspend/revoke journey, historical active controls, TRQP decisions,
and VC consumer status updates now run through
`scripts/governed-demo-issuer-temporal.mjs`. It publishes both simulator
snapshots through the outer demo's callback so the API reads the updated
state; replacing that callback with a local snapshot would make the HTTP
assertions stale. The case IDs and final actor report remain unchanged, and
the isolated matrix remains the independent failure-accounting lane. This is
still fixture and simulator evidence, not a deployed lifecycle observation.
The verifier, auditor, and recognition suspend/revoke loop now runs through
`scripts/governed-demo-other-temporal.mjs`. It retains the role-specific
historical API/TRQP decisions, recognition evidence verification, and verifier
VC consumer status updates. The demo supplies the snapshot-publication
callback so each subsequent HTTP read observes the changed simulator state.
The final `otherTemporalChecks` and verifier lifecycle report keep the same
shape; isolated case-ID parity must still pass before treating this as a
behavior-preserving extraction.

At signed local source `bbb2c456a93aa035ac482d67f945e8cddf6dfb7c`, the
private archive `artifacts/adversarial-reports/cases-bbb2c456a93aa035ac482d67f945e8cddf6dfb7c.json`
recorded 198/198 isolated passes and 198 governed-demo case IDs, with report
SHA-256 `4dc5ccfecd389c26c234673fd5178e2f3ada32efea14718bd2ae090870c8280b`.
This is an intermediate local source, not the final RC revision or a deployed
ledger result. The Compact proposal circuit accepts a signed evidence hash but
has no trusted time input; the expired-evidence cases currently reject at
intake/preflight, not as a submitted Compact expiry check. Do not attribute
that boundary to Compact or close #60 without reconciling its tracker scope.

The governed demo also emits `actorReport` in
`tr-actor-evidence-report-v1` format. It records one active decision for each
issuer, verifier, auditor, recognition, and maintainer actor, with policy
version, observed epoch, two distinct activation signer key IDs, expected and
observed result, and IDs of checked rule-specific rejections. The report is a
strict projection of public decision evidence; it does not copy applications,
VCs, VPs, or holder data. It is simulator evidence, not a finalized network
attestation.
