# Adversarial Matrix Coverage

Issue [#60](https://github.com/midnightntwrk/midnight-trust-registry/issues/60)
tracks an end-to-end rejection matrix. This table distinguishes the checked
`adversarialMatrix.cases` report from ordinary unit tests and from unrecorded
demo assertions. `Observed` means the demo asserts a real rejection and records
the case; it does not imply production-network proving or finality.

| Requirement | Current evidence | Gap |
| --- | --- | --- |
| Self-approval | `maintainer-approve-candidate-self-vote`, `maintainer-activate-candidate-self-vote` reject the candidate key through the API | The candidate may fail active-signer lookup before Compact's explicit self-DID exclusion; prove that assertion separately. |
| Duplicate signer | `compact-issuer-duplicate-signer`, role-specific `*-proposal-duplicate-signer`, and role-specific `duplicate-signer` API action cases | Add Compact proposal-level duplicate-signer cases outside the issuer fixture. |
| Insufficient quorum | `compact-issuer-insufficient-quorum`, role-specific API action and `*-proposal-insufficient-quorum` cases; `compact-old-policy-signature-replay` rejects a signature after threshold revision; `policy-revision-one-signer` and `new-policy-registration-two-signers` exercise the two policy phases over HTTP | Add cross-role policy-transition vectors. |
| Key substitution | `compact-issuer-unknown-signer`, `compact-removed-maintainer-signer` | Add a changed-key DID method. |
| Last active maintainer | `compact-last-active-maintainer`, `compact-last-active-maintainer-revocation` | Both suspend and revoke preserve the active count and governance sequence. |
| Altered evidence commitment | `issuer-altered-evidence-commitment-api`, `issuer-altered-evidence-commitment-integration-preflight`, `compact-issuer-altered-evidence-hash` | Add a signed proposal-level evidence-hash mutation. |
| Altered policy ID/version | `issuer-signed-wrong-policy-id`, `issuer-uncommitted-policy-version`, `integration-old-policy-application-preflight`, `compact-old-policy-signature-replay`, and `policy-revision-stale-replay` over HTTP | Add a changed-policy version on another governed role. |
| Expired evidence and unauthorized evidence verifier | `issuer-expired-signed-application-evidence`, role-specific `*-expired-evidence-api-preflight` and `*-expired-accepted-evidence-api` for issuer, verifier, auditor, and maintainer proposals; `issuer-unauthorized-evidence-verifier-api`, `issuer-unauthorized-evidence-verifier-compact` | Add a submitted Compact action with expired evidence; epoch expiry is separately checked by `issuer-expired-epoch`. |
| Issuer/verifier scope mismatch | `issuer-wrong-credential-family`, `verifier-wrong-request-profile`, `issuer-wrong-resource-api`, `verifier-wrong-resource-api`; issuer signed VP scope case | Add a governed-action payload scope mutation. |
| Stale epoch and tampered Merkle path | `issuer-expired-epoch`, `issuer-tampered-merkle-path`, `issuer-historical-proof-tampered-after-policy-revision`, `issuer-historical-epoch-signature-tampered`; issuer historical API/TRQP decision parity after suspension and revocation | Add a separately anchored public-query proof freshness case. |
| External recognition as authorization | `recognition-not-issuer-authorization`, `recognition-wrong-external-registry-api`, `trqp-wrong-recognized-registry`; `compact-recognition-external-registry-substitution` and `compact-recognition-resource-substitution` reject reuse of a valid signed proposal under a changed Compact input | Add independent external accreditation validation before public recognition intake. |
| Historical state after suspension/revocation | Role-specific `historical-after-suspension` and `historical-after-revocation` client cases verify issuer, verifier, auditor, and recognition evidence; `*-historical-api-after-*` cases check public lookups at the same instants; issuer, verifier, and recognition `*-trqp` cases check decision parity | Auditor TRQP is not mapped by the adapter; define the protocol action before adding parity. |
| Historical state after threshold change | `issuer-history-survives-threshold-change`, `issuer-current-policy-after-threshold-change`, `issuer-old-policy-current-time-replay` | Add the same transition through a public API historical query. |

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
