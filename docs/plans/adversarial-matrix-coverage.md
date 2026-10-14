# Adversarial Matrix Coverage

Issue [#60](https://github.com/midnightntwrk/midnight-trust-registry/issues/60)
tracks an end-to-end rejection matrix. This table distinguishes the checked
`adversarialMatrix.cases` report from ordinary unit tests and from unrecorded
demo assertions. `Observed` means the demo asserts a real rejection and records
the case; it does not imply production-network proving or finality.

| Requirement | Current evidence | Gap |
| --- | --- | --- |
| Self-approval | `maintainer-approve-candidate-self-vote`, `maintainer-activate-candidate-self-vote` reject the candidate key through the API | The candidate may fail active-signer lookup before Compact's explicit self-DID exclusion; prove that assertion separately. |
| Duplicate signer | `compact-issuer-duplicate-signer` and role-specific `duplicate-signer` API action cases | Add proposal-level duplicate-signer checks. |
| Insufficient quorum | `compact-issuer-insufficient-quorum`, role-specific API action and proposal cases; `compact-old-policy-signature-replay` rejects a signature after threshold revision | Add cross-role policy-transition vectors. |
| Key substitution | `compact-issuer-unknown-signer`, `compact-removed-maintainer-signer` | Add a changed-key DID method. |
| Last active maintainer | `compact-last-active-maintainer`, `compact-last-active-maintainer-revocation` | Both suspend and revoke preserve the active count and governance sequence. |
| Altered evidence commitment | `issuer-altered-evidence-commitment-api`, `issuer-altered-evidence-commitment-integration-preflight`, `compact-issuer-altered-evidence-hash` | Add a signed proposal-level evidence-hash mutation. |
| Altered policy ID/version | `issuer-signed-wrong-policy-id`, `issuer-uncommitted-policy-version`, `integration-old-policy-application-preflight`, `compact-old-policy-signature-replay` | Add API-boundary revision cases. |
| Expired evidence and unauthorized evidence verifier | `issuer-expired-signed-application-evidence`, `issuer-expired-evidence-api-preflight`, `issuer-expired-accepted-evidence-api`, `issuer-unauthorized-evidence-verifier-api`, `issuer-unauthorized-evidence-verifier-compact` | Extend expiry coverage to the other governed proposal roles; epoch expiry is separately checked by `issuer-expired-epoch`. |
| Issuer/verifier scope mismatch | `issuer-wrong-credential-family`, `verifier-wrong-request-profile`, `issuer-wrong-resource-api`, `verifier-wrong-resource-api`; issuer signed VP scope case | Add a governed-action payload scope mutation. |
| Stale epoch and tampered Merkle path | `issuer-expired-epoch`, `issuer-tampered-merkle-path`, `issuer-historical-proof-tampered-after-policy-revision`, `issuer-historical-epoch-signature-tampered`; issuer historical API/TRQP decision parity after suspension and revocation | Add a separately anchored public-query proof freshness case. |
| External recognition as authorization | `recognition-not-issuer-authorization`, `recognition-wrong-external-registry-api`, `trqp-wrong-recognized-registry` | Add a Compact recognition-action scope mutation. |
| Historical state after suspension/revocation | Role-specific `historical-after-suspension` and `historical-after-revocation` client cases verify issuer, verifier, auditor, and recognition evidence; `*-historical-api-after-*` cases check public lookups at the same instants; issuer `*-trqp` cases check authorization parity | Extend TRQP historical parity to verifier, auditor, and recognition where their request mappings apply. |
| Historical state after threshold change | `issuer-history-survives-threshold-change`, `issuer-current-policy-after-threshold-change`, `issuer-old-policy-current-time-replay` | Add the same transition through a public API historical query. |

The report has API, Compact simulator, integration preflight, client, and TRQP
adapter entries. The
same invariant is **not yet** exercised at every relevant boundary, so issue
#60 remains open. Compact simulator failures are not proof of a submitted
Midnight transaction; the fixture uses deterministic local time and finality.
