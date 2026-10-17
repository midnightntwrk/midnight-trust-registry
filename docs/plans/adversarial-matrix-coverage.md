# Adversarial Matrix Coverage

Issue [#60](https://github.com/midnightntwrk/midnight-trust-registry/issues/60)
tracks an end-to-end rejection matrix. This table distinguishes the checked
`adversarialMatrix.cases` report from ordinary unit tests and from unrecorded
demo assertions. `Observed` means the demo asserts a real rejection and records
the case; it does not imply production-network proving or finality.

| Requirement | Current evidence | Gap |
| --- | --- | --- |
| Self-approval | `maintainer-approve-candidate-self-vote`, `maintainer-activate-candidate-self-vote` reject the candidate key through the API; `trust-registry.test.ts` separately passes an active target maintainer's valid signature as a co-signer and observes Compact's `own DID` rejection without advancing governance state | The public candidate route may reject earlier at active-signer lookup; do not present that API response as the proof of Compact's self-DID exclusion. |
| Duplicate signer | `compact-issuer-duplicate-signer`, role-specific `*-proposal-duplicate-signer` and `compact-*-proposal-duplicate-signer` cases for issuer, verifier, auditor, and maintainer, plus role-specific `duplicate-signer` API action cases. The direct Compact proposal cases leave governance state unchanged | These four membership proposal roles are covered; recognition is a separate governed-resource path. |
| Insufficient quorum | `compact-issuer-insufficient-quorum`, role-specific API action and `*-proposal-insufficient-quorum` cases, and direct `compact-*-proposal-insufficient-quorum` cases for all four membership roles; `compact-old-policy-signature-replay` rejects an issuer signature after threshold revision; `policy-revision-one-signer` and `new-policy-registration-two-signers` exercise the two policy phases over HTTP; role-specific `*-revised-policy-insufficient-quorum` and `*-current-policy-after-threshold-change` cases cover revised-quorum rejection and activation for verifier, auditor, and maintainer | Old-policy action-signature replay is exercised for issuer only; do not infer cross-role replay coverage from revised-quorum cases. |
| Key substitution | `compact-issuer-unknown-signer`, `compact-removed-maintainer-signer` | Add a changed-key DID method. |
| Maintainer removal threshold | `compact-self-voted-maintainer-suspension`, `compact-self-voted-maintainer-revocation`, and `compact-removal-below-maintainer-threshold` | Self-votes are rejected; a separate non-conflicted signer cannot remove a maintainer when that would leave fewer active maintainers than the live threshold. The one-maintainer case cannot supply a non-conflicted signer. |
| Altered evidence commitment | `issuer-altered-evidence-commitment-api`, `issuer-altered-evidence-commitment-integration-preflight`, `compact-issuer-altered-evidence-hash`, and role-specific `compact-*-proposal-altered-evidence-hash` cases for issuer, verifier, auditor, and maintainer. Each proposal case changes only the Compact evidence hash while retaining valid maintainer and verifier signatures, and checks that governance state does not advance | The four membership proposal roles are covered at this boundary. Recognition accreditation uses a separate authority-proof path; do not infer its coverage from these cases. |
| Altered policy ID/version | `issuer-signed-wrong-policy-id`, `issuer-uncommitted-policy-version`, `integration-old-policy-application-preflight`, `compact-old-policy-signature-replay`, and `policy-revision-stale-replay` over HTTP | Add a changed-policy version on another governed role. |
| Expired evidence and unauthorized evidence verifier | `issuer-expired-signed-application-evidence`, role-specific `*-expired-evidence-api-preflight` and `*-expired-accepted-evidence-api` for issuer, verifier, auditor, and maintainer proposals; `issuer-unauthorized-evidence-verifier-api`, `issuer-unauthorized-evidence-verifier-compact` | Add a submitted Compact action with expired evidence; epoch expiry is separately checked by `issuer-expired-epoch`. |
| Issuer/verifier scope mismatch | `issuer-wrong-credential-family`, `verifier-wrong-request-profile`, `issuer-wrong-resource-api`, `verifier-wrong-resource-api`; issuer signed VP scope case | Add a governed-action payload scope mutation. |
| Stale epoch and tampered Merkle path | `issuer-expired-epoch`, `issuer-tampered-merkle-path`, `issuer-historical-proof-tampered-after-policy-revision`, `issuer-historical-epoch-signature-tampered`; issuer historical API/TRQP decision parity after suspension and revocation | Add a separately anchored public-query proof freshness case. |
| External recognition as authorization | `recognition-not-issuer-authorization`, `recognition-wrong-external-registry-api`, `trqp-wrong-recognized-registry`; `compact-recognition-external-registry-substitution` and `compact-recognition-resource-substitution` reject reuse of a valid signed proposal under a changed Compact input | Add independent external accreditation validation before public recognition intake. |
| Historical state after suspension/revocation | Role-specific `historical-after-suspension` and `historical-after-revocation` client cases verify issuer, verifier, auditor, and recognition evidence; `*-historical-api-after-*` cases check public lookups at the same instants; issuer, verifier, and recognition `*-trqp` cases check decision parity | Auditor TRQP is not mapped by the adapter; define the protocol action before adding parity. |
| Historical state after threshold change | `issuer-history-survives-threshold-change`, `issuer-current-policy-after-threshold-change`, `issuer-old-policy-current-time-replay`, and `issuer-historical-api-after-threshold-change` in the machine-readable demo report; `governed-policy-http.integration.test.ts` also checks that native and TRQP historical HTTP evidence retain the old issuer epoch and policy version after a Compact-backed threshold revision | This transition is now represented in the report and the API integration suite; the other row-specific gaps still keep #60 open. |

The report has API, Compact simulator, integration preflight, client, and TRQP
adapter entries. The
same invariant is **not yet** exercised at every relevant boundary, so issue
#60 remains open. Compact simulator failures are not proof of a submitted
Midnight transaction; the fixture uses deterministic local time and finality.

The governed demo also emits `actorReport` in
`tr-actor-evidence-report-v1` format. It records one active decision for each
issuer, verifier, auditor, recognition, and maintainer actor, with policy
version, observed epoch, two distinct activation signer key IDs, expected and
observed result, and IDs of checked rule-specific rejections. The report is a
strict projection of public decision evidence; it does not copy applications,
VCs, VPs, or holder data. It is simulator evidence, not a finalized network
attestation.
