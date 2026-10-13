# Adversarial Matrix Coverage

Issue [#60](https://github.com/midnightntwrk/midnight-trust-registry/issues/60)
tracks an end-to-end rejection matrix. This table distinguishes the checked
`adversarialMatrix.cases` report from ordinary unit tests and from unrecorded
demo assertions. `Observed` means the demo asserts a real rejection and records
the case; it does not imply production-network proving or finality.

| Requirement | Current evidence | Gap |
| --- | --- | --- |
| Self-approval | `maintainer-approve-candidate-self-vote`, `maintainer-activate-candidate-self-vote` | Also exercise the Compact boundary directly. |
| Duplicate signer | `compact-issuer-duplicate-signer` | Add API duplicate-signer combination. |
| Insufficient quorum | `compact-issuer-insufficient-quorum`, role-specific API action and proposal cases; `compact-old-policy-signature-replay` rejects a signature after threshold revision | Add cross-role policy-transition vectors. |
| Key substitution | `compact-issuer-unknown-signer`, `compact-removed-maintainer-signer` | Add a changed-key DID method. |
| Last active maintainer | `compact-last-active-maintainer` | Add another critical lifecycle operation. |
| Altered evidence commitment | `issuer-altered-evidence-commitment-api`, `issuer-altered-evidence-commitment-integration-preflight` | Add a circuit-level mutated evidence-hash witness; the preflight is not Compact execution. |
| Altered policy ID/version | `issuer-uncommitted-policy-version`, `integration-old-policy-application-preflight`, `compact-old-policy-signature-replay` | Add policy-ID substitution and API-boundary revision cases. |
| Expired evidence and unauthorized evidence verifier | `issuer-expired-epoch`, `issuer-unauthorized-evidence-verifier-api`, `issuer-unauthorized-evidence-verifier-compact` | Add expiry of applicant evidence; epoch expiry is a different invariant. |
| Issuer/verifier scope mismatch | `issuer-wrong-credential-family`, `verifier-wrong-request-profile`; issuer signed VP scope case | Add cross-surface scope vectors. |
| Stale epoch and tampered Merkle path | `issuer-expired-epoch`, `issuer-tampered-merkle-path` | Add a historical proof mutation after policy change. |
| External recognition as authorization | `recognition-not-issuer-authorization` | Add direct recognition scope mismatch at adapter boundary. |
| Historical state after suspension/revocation | Role-specific `historical-after-suspension` and `historical-after-revocation` client cases verify issuer, verifier, auditor, and recognition evidence | Add negative mutations against the archived historical proof. |
| Historical state after threshold change | `issuer-history-survives-threshold-change`, `issuer-current-policy-after-threshold-change`, `issuer-old-policy-current-time-replay` | Add the same transition through a public API historical query. |

The report has API, Compact simulator, integration preflight, client, and TRQP
adapter entries. The
same invariant is **not yet** exercised at every relevant boundary, so issue
#60 remains open. Compact simulator failures are not proof of a submitted
Midnight transaction; the fixture uses deterministic local time and finality.
