# Standalone Security Script Type Boundary

Issue #229 tracks typed assurance for the self-hosted 0.1.0 installer and
operator workflow. The existing broad `checkJs` configuration includes the
wizard and installer but permits implicit `any`; Quality CI now runs it.
A second, strict no-emit gate runs
`pnpm run check:security-boundaries-types` for eleven privileged boundaries:

| Checked file | Security decision |
| --- | --- |
| `scripts/approved-provider-identity.mjs` | Hash and inode continuity across provider loading. |
| `scripts/immutable-provider-tree.mjs` | Root-owned code tree and import confinement. |
| `scripts/provider-runtime-content.mjs` | Content digest and file continuity during the reviewed provider transfer. |
| `scripts/check-published-package-integrity.mjs` | Existing npm-version SHA-512 match before an idempotent publish skip. |
| `scripts/standalone-approval-policy.mjs` | Canonical reviewer metadata and release committee/custody validation. |
| `scripts/standalone-acceptance-decision-policy.mjs` | Source-bound operator decision history and current evidence coverage. |
| `scripts/standalone-api-approval-chain.mjs` | Exact-byte approval-chain export and deployment/maintenance readback binding. |
| `scripts/standalone-genesis-review-policy.mjs` | Untrusted candidate and proposed pin comparison against a verified profiled install. |
| `scripts/standalone-journey-prerequisites-policy.mjs` | Fail-closed wizard-status gate decisions before an offline actor run. |
| `scripts/standalone-image-reference.mjs` | Shared pinned OCI reference syntax for installer and review policy. |
| `scripts/verify-helm-mapping-signature.mjs` | Optional Helm mapping signature and pinned keyring. |

Quality CI runs both gates after workspace typechecking. Runtime tests still
exercise path replacement, writable imports, signer substitution, and weak
GPG statuses. A passing type gate is not evidence of an approved provider
installation, human review, or live deployment.

## Remaining non-strict decision surface

Owner: Trust Registry 0.1.0 release engineering. These files are included in
the broad `tsconfig.security-scripts.json` configuration where applicable, but their
decision inputs are not yet strictly typed. This is a tracked migration
inventory, not a waiver of the release security review.

| Priority | Files | Reason to retain until typed |
| --- | --- | --- |
| 1 | `scripts/standalone-setup-wizard.mjs`, `scripts/prepare-standalone-genesis-review.mjs` | Signed genesis, committee, deployment, and recovery approval sequencing. Reviewer metadata, committee validation, untrusted genesis-review comparison, and API approval-chain export are strictly checked; remaining transitions and the I/O shell still need migration. |
| 2 | `scripts/local-ledger-deploy.mjs`, `scripts/local-ledger-insert-verifier-key.mjs`, `scripts/stage-provider-runtime.mjs` | Privileged provider material, one-attempt journals, and exact-source install. The direct deployment and insertion CLIs are disabled; the wizard imports these functions after approval checks. |
| 3 | `scripts/build-standalone-install.mjs`, `scripts/load-standalone-install-images.mjs`, `scripts/check-standalone-install.mjs` | Source and OCI image pin decisions. Keep hash and path validation identical while moving pure validators to typed code. |
| 4 | `scripts/check-helm-image-mapping.mjs`, `scripts/observe-helm-runtime.mjs` | Optional Kubernetes mapping and observations; Helm is not a 0.1.0 RC gate. |
| 5 | `scripts/release-candidate-manifest.mjs`, `scripts/check-publish-tarball.mjs` | Release package and verifier-key hash decisions; manifest-backed publish remains a separate release gate. |

The standalone acceptance inventory checker is included in the broad
`checkJs` gate. Its decision-chain policy is also in the strict gate; the
private-file reads and candidate identity comparison remain runtime-tested in
the non-strict I/O shell. Neither gate authenticates operator evidence or
replaces independent review.

The journey-prerequisite policy is strictly checked separately from its CLI
adapter, which imports the still non-strict wizard. The policy rejects
malformed status and fails the verifier-key gate on malformed entries; it
checks only wizard-recorded state. It does not verify independent finality,
signed API plans, egress denial, or an actor transaction.

Each migration should add malformed/missing-field negatives, preserve the
existing exact-byte and journal behavior, and run its focused tests before
expanding `tsconfig.security-boundaries.json`. Do not treat the broad gate's
implicit `any` allowance as proof that the wizard's decision inputs are
strictly typed. The remaining inventory and independent human review stay
open before local RC qualification.
