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
| Insufficient quorum | `compact-issuer-insufficient-quorum`, role-specific API action and `*-proposal-insufficient-quorum` cases, and direct `compact-*-proposal-insufficient-quorum` cases for all four membership roles; `compact-old-policy-signature-replay` and `compact-{verifier,auditor,maintainer}-old-policy-signature-replay` reject former-policy signatures after threshold revision; `policy-revision-one-signer` and `new-policy-registration-two-signers` exercise the two policy phases over HTTP; role-specific `*-revised-policy-insufficient-quorum` and `*-current-policy-after-threshold-change` cases cover revised-quorum rejection and activation | Old-policy replay is exercised for membership approval actions, not every lifecycle action or recognition. |
| Key substitution | `compact-issuer-unknown-signer`, `compact-removed-maintainer-signer`, and `issuer-vp-holder-method-substitution` reject unknown governance keys and a post-signing VP method-reference change; `recognition-intake-rotated-authority-did-key` rejects an assertion signed before the resolved authority DID key changes | The recognition assertion covers a real resolved-key change, but not holder or maintainer DID rotation. A changed proof method reference is not the same as a changed resolved DID key. |
| Maintainer removal threshold | `compact-self-voted-maintainer-suspension`, `compact-self-voted-maintainer-revocation`, and `compact-removal-below-maintainer-threshold` | Self-votes are rejected; a separate non-conflicted signer cannot remove a maintainer when that would leave fewer active maintainers than the live threshold. The one-maintainer case cannot supply a non-conflicted signer. |
| Altered evidence commitment | `issuer-altered-evidence-commitment-api`, `issuer-altered-evidence-commitment-integration-preflight`, `compact-issuer-altered-evidence-hash`, and role-specific `compact-*-proposal-altered-evidence-hash` cases for issuer, verifier, auditor, and maintainer. Each proposal case changes the Compact evidence hash, re-signs it with the authorized evidence-verifier key, retains the old maintainer signatures, and checks that governance state does not advance | The four membership proposal roles are covered at this boundary. Recognition accreditation uses a separate authority-proof path; do not infer its coverage from these cases. |
| Altered policy ID/version | `issuer-signed-wrong-policy-id`, `issuer-uncommitted-policy-version`, `verifier-uncommitted-policy-version`, `integration-old-policy-application-preflight`, `compact-old-policy-signature-replay`, and `policy-revision-stale-replay` over HTTP | Issuer and verifier bundle policy versions are checked; auditor and recognition have separate policy evidence paths. |
| Expired evidence and unauthorized evidence verifier | `issuer-expired-signed-application-evidence`, role-specific `*-expired-evidence-api-preflight` and `*-expired-accepted-evidence-api` for issuer, verifier, auditor, and maintainer proposals; `issuer-unauthorized-evidence-verifier-api`, `issuer-unauthorized-evidence-verifier-compact` | Add a submitted Compact action with expired evidence; epoch expiry is separately checked by `issuer-expired-epoch`. |
| Issuer/verifier scope mismatch | `issuer-wrong-credential-family`, `verifier-wrong-request-profile`, `issuer-wrong-resource-api`, `verifier-wrong-resource-api`; issuer signed VP scope case. `compact-{issuer,verifier,auditor}-proposal-scope-substitution` re-signs altered verifier evidence but retains the original maintainer quorum, proving the changed Compact proposal payload is rejected while fresh signatures would execute | Recognition proposal scope substitution is separately checked; these simulator checks are not a submitted network transaction. |
| Stale epoch and tampered Merkle path | `issuer-expired-epoch`, `issuer-tampered-merkle-path`, `issuer-historical-proof-tampered-after-policy-revision`, `issuer-historical-epoch-signature-tampered`; issuer historical API/TRQP decision parity after suspension and revocation | Add a separately anchored public-query proof freshness case. |
| External recognition as authorization | `recognition-not-issuer-authorization`, `recognition-wrong-external-registry-api`, `trqp-wrong-recognized-registry`; `compact-recognition-external-registry-substitution` and `compact-recognition-resource-substitution` reject reuse of a valid signed proposal under a changed Compact input. Six `recognition-intake-*` cases reject registry/signature/policy/status/VP/key substitution in composed challenge and accreditation verification, then accept the valid fixture without consuming the challenge on failure | The accreditation anchor, status, and DID state are local fixtures; independent external accreditation and public-network finality remain unproven. |
| Historical state after suspension/revocation | Role-specific `historical-after-suspension` and `historical-after-revocation` client cases verify issuer, verifier, auditor, and recognition evidence; `*-historical-api-after-*` cases check public lookups at the same instants; issuer, verifier, and recognition `*-trqp` cases check decision parity | Auditor TRQP is not mapped by the adapter; define the protocol action before adding parity. |
| Historical state after threshold change | `issuer-history-survives-threshold-change`, `issuer-current-policy-after-threshold-change`, `issuer-old-policy-current-time-replay`, `issuer-historical-api-after-threshold-change`, and `issuer-historical-trqp-after-threshold-change` in the machine-readable demo report; isolated Node cases and `governed-policy-http.integration.test.ts` check that native and TRQP historical HTTP evidence retain the old issuer epoch and policy version after a Compact-backed threshold revision. `verifier-history-survives-threshold-change`, `verifier-historical-api-after-threshold-change`, and `verifier-historical-trqp-after-threshold-change` retain a pre-revision active verifier bundle through a later threshold change and revocation. | Issuer and verifier evidence are covered at the client, API, and TRQP simulator boundaries; auditor and recognition threshold-history paths remain unproven here. |

The report has API, Compact simulator, integration preflight, client, and TRQP
adapter entries. The
same invariant is **not yet** exercised at every relevant boundary, so issue
#60 remains open. Compact simulator failures are not proof of a submitted
Midnight transaction; the fixture uses deterministic local time and finality.

`pnpm run adversarial:report` runs the isolated Node test cases and writes a
`tr-adversarial-case-report-v1` JSON object to stdout. Its sorted case results
include a stable pass/fail reason code; a failing case does not stop later
cases. The command exits nonzero on a failed case or a count other than 189.
`pnpm run check:adversarial-parity -- --require-full` additionally compares
those isolated case IDs with the governed demo's machine-readable matrix.
The demo remains useful as one sequential actor journey, but its independent
case report is the regression gate when an earlier journey step fails.

The governed demo also emits `actorReport` in
`tr-actor-evidence-report-v1` format. It records one active decision for each
issuer, verifier, auditor, recognition, and maintainer actor, with policy
version, observed epoch, two distinct activation signer key IDs, expected and
observed result, and IDs of checked rule-specific rejections. The report is a
strict projection of public decision evidence; it does not copy applications,
VCs, VPs, or holder data. It is simulator evidence, not a finalized network
attestation.
