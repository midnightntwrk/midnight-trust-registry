# Adversarial Matrix Coverage

Issue [#60](https://github.com/midnightntwrk/midnight-trust-registry/issues/60)
tracks an end-to-end rejection matrix. This table distinguishes the checked
`adversarialMatrix.cases` report from ordinary unit tests and from unrecorded
demo assertions. `Observed` means the demo asserts a real rejection and records
the case; it does not imply production-network proving or finality.

| Requirement | Current evidence | Gap |
| --- | --- | --- |
| Self-approval | `maintainer-approve-candidate-self-vote`, `maintainer-activate-candidate-self-vote` | Also exercise the Compact boundary directly. |
| Duplicate signer | `compact-issuer-duplicate-signer` | Add API and removed-signer combinations. |
| Insufficient quorum | `compact-issuer-insufficient-quorum`, role-specific API action and proposal cases | Add policy-threshold-change replay. |
| Key substitution | `compact-issuer-unknown-signer` | Add revoked/removed key and a changed-key DID method. |
| Last active maintainer | Unit test only | Add to the matrix. |
| Altered evidence commitment | VP body binding case only | Tamper the governed proposal evidence commitment. |
| Altered policy ID/version | Not in matrix | Reject old or substituted policy snapshots at contract and API boundaries. |
| Expired evidence and unauthorized evidence verifier | Expired epoch client case only | Add expiry of applicant evidence and nonmember verifier key. |
| Issuer/verifier scope mismatch | `issuer-wrong-credential-family`, `verifier-wrong-request-profile`; issuer signed VP scope case | Add cross-surface scope vectors. |
| Stale epoch and tampered Merkle path | `issuer-expired-epoch`, `issuer-tampered-merkle-path` | Add a historical proof mutation after policy change. |
| External recognition as authorization | `recognition-not-issuer-authorization` | Add direct recognition scope mismatch at adapter boundary. |
| Historical state after suspension/revocation | Demo asserts issuer, verifier, auditor, and recognition historical trust remains true | Record verified historical outcomes as matrix cases. |
| Historical state after threshold change | Not in matrix | Exercise old and new policy snapshots around the threshold transition. |

The report has API, Compact simulator, client, and TRQP adapter entries. The
same invariant is **not yet** exercised at every relevant boundary, so issue
#60 remains open. Compact simulator failures are not proof of a submitted
Midnight transaction; the fixture uses deterministic local time and finality.
