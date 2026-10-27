# Standalone Security Script Type Boundary

Issue #229 tracks typed assurance for the self-hosted 0.1.0 installer and
operator workflow. The existing broad `checkJs` configuration includes the
wizard and installer but permits implicit `any`; Quality CI now runs it.
A second, strict no-emit gate runs
`pnpm run check:security-boundaries-types` for forty-six privileged boundaries:

| Checked file | Security decision |
| --- | --- |
| `scripts/approved-provider-identity.mjs` | Hash and inode continuity across provider loading. |
| `scripts/immutable-provider-tree.mjs` | Root-owned code tree and import confinement. |
| `scripts/local-ledger-preflight.mjs` | Reusable exact-field local genesis pin validation before wizard access-path selection or node observation; its output remains node-reported and unapproved. |
| `scripts/local-ledger-deploy.mjs` | Typed deployment/reconciliation shell, staged versus full submission inputs, and early manifest catalog validation; provider factory output remains a reviewed dynamic-code boundary. |
| `scripts/local-ledger-insert-verifier-key.mjs` | Typed staged key-insertion/reconciliation shell, approved deployment receipt comparison, and early manifest catalog validation. |
| `scripts/local-deployment-plan-policy.mjs` | Exact source, network, provider, and journal fields before deployment or key insertion. |
| `scripts/local-verifier-key-insertion-plan-policy.mjs` | Exact verifier-key insertion approval and fixed per-circuit journal path. |
| `scripts/package-contents-policy.mjs` | Full Compact proof-circuit name and artifact completeness decisions. |
| `scripts/provider-runtime-content.mjs` | Content digest and file continuity during the reviewed provider transfer. |
| `scripts/stage-provider-runtime.mjs` | Signed-source archive and verified-package staging, private target, and byte-for-byte source checks before operator ownership transfer. |
| `scripts/provider-stage-package-policy.mjs` | Exact expected workspaces, unique archive names, and SHA-256 catalog fields before provider staging. |
| `scripts/release-candidate-manifest.mjs` | Exact package, source, compiler, and verifier-key manifest construction and verification. |
| `scripts/check-published-package-integrity.mjs` | Existing npm-version SHA-512 match before an idempotent publish skip. |
| `scripts/check-publish-tarball.mjs` | Exact package name/version, size, and digest at the final npm tarball handoff. |
| `scripts/check-standalone-install.mjs` | Install inventory, pinned OCI archive, Compose, API/portal image, relay, and proof-parameter byte verification. Parsed OCI JSON uses explicitly dynamic callback shapes with runtime validation. |
| `scripts/build-standalone-install.mjs` | Exact-source install inputs, local pinned-image checks, immutable preflight image-directory selection, and new-bundle construction. |
| `scripts/load-standalone-install-images.mjs` | Verified archive snapshots and Docker ID/tag matching without a registry pull. |
| `scripts/standalone-approval-policy.mjs` | Canonical reviewer metadata and release committee/custody validation. |
| `scripts/check-standalone-actor-capability.mjs` | Fail-closed signed-plan and configured-role preflight before a deployed actor run; does not authenticate finality or execute a transaction. |
| `scripts/standalone-acceptance-decision-policy.mjs` | Source-bound operator decision history and current evidence coverage. |
| `scripts/standalone-acceptance-manifest-policy.mjs` | Strictly typed shape and source/deployment identity validation for untrusted acceptance manifests; it does not authenticate attached evidence. |
| `scripts/check-standalone-acceptance-evidence.mjs` | Strictly checked private-file I/O, attachment and verdict sequencing, observation binding, and exact-byte evidence hashing. Runtime validation remains mandatory for parsed JSON. |
| `scripts/standalone-api-approval-chain.mjs` | Exact-byte approval-chain export and deployment/maintenance readback binding. |
| `scripts/standalone-genesis-review-policy.mjs` | Untrusted candidate and proposed pin comparison against a verified profiled install. |
| `scripts/standalone-genesis-review-packet.mjs` | Typed rendering of the untrusted human genesis review packet; its digests and contents cannot become an approval. |
| `scripts/standalone-genesis-review-io.mjs` | Private packet input reads, verified-bundle handoff, and non-overwriting output bytes. The bundle verifier itself remains non-strict. |
| `scripts/prepare-standalone-genesis-review.mjs` | Strictly typed packet entrypoint and injectable verified-bundle callback; it does not independently approve the proposed pin. |
| `scripts/standalone-journey-prerequisites-policy.mjs` | Fail-closed wizard-status gate decisions before an offline actor run. |
| `scripts/standalone-qualification-scope-policy.mjs` | Rejects current-query and API-restart child reports that claim unobserved actor, finality, host/browser egress, deployment binding, or release qualification. |
| `scripts/standalone-current-query-process-policy.mjs` | Requires a valid container ID, process start time, and restart count before the current-query observer compares reads around egress. |
| `scripts/standalone-private-file-bytes.mjs` | Bounded, no-follow reads of private setup and approval evidence with inode and ownership continuity. |
| `scripts/standalone-image-reference.mjs` | Shared pinned OCI reference syntax for installer and review policy. |
| `scripts/standalone-compose-image-policy.mjs` | Exact base Compose project, role map, and digest-pinned image decisions before inventory comparison. It does not validate overlays or deployed topology. |
| `scripts/standalone-install-image-inventory-policy.mjs` | Exact ledger image roles, unique archive mapping, and digest pins before archive I/O. It does not authenticate archive contents or installed runtime. |
| `scripts/standalone-egress-route-policy.mjs` | Canonical ledger subnet, route-table mask, and local canary denial decisions shared by egress observers. It does not exercise running services or prove general DNS isolation. |
| `scripts/check-standalone-topology.mjs` | Checked Docker inspect shapes and dedicated ledger network, container, image, port, mount, and private-input comparisons. Inspect JSON remains untrusted runtime data. |
| `scripts/check-standalone-egress.mjs` | Checked Docker command/result handoff and verified-bundle topology binding; the canary probe is limited observation, not general egress or actor evidence. |
| `scripts/standalone-egress-canary-scripts.mjs` | One shared source for the offline HTTP and DNS/UDP canary programs used by API and ledger probes. |
| `scripts/check-standalone-local-egress.mjs` | Checked local positive/negative canary probe command/result handoff and cleanup; a passing probe does not establish full host or actor egress denial. |
| `scripts/check-standalone-api-runtime.mjs` | Checked Docker API-container topology, pinned image/env/command, approval mount, process identity, and non-public listener decisions. Parsed Docker JSON remains untrusted. |
| `scripts/check-standalone-api-egress.mjs` | Checked API canary positive/negative control orchestration and cleanup. It does not establish full DNS isolation, independent finality, or actor egress denial. |
| `scripts/standalone-api-egress-policy.mjs` | Requires live positive controls and confined API routes, and accepts only specified TCP and DNS route-denial results. Docker probe orchestration and broader protocol coverage remain outside this typed decision. |
| `scripts/standalone-docker-probe-command.mjs` | Strictly typed Docker command result and zero-exit enforcement for the API egress observer. Live Docker/network observation remains outside this helper. |
| `scripts/runtime-healthcheck.mjs` | Exact runtime healthcheck shape for the API and static portals. |
| `scripts/static-runtime-archive.mjs` | Untrusted Docker/OCI image metadata, runtime identity, and static asset manifest decisions. |
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
| 1 | `scripts/standalone-setup-wizard.mjs` | Signed genesis, committee, deployment, and recovery approval sequencing. Reviewer metadata, committee validation, untrusted genesis-review comparison, packet rendering and private packet I/O, packet entrypoint, private-file reads, and API approval-chain export are strictly checked; the wizard transitions remain non-strict. |
| 2 | Provider runtime installation/ownership transfer | The staging shell and install-bundle verifier are now strictly checked; the actual root-owned transfer and independently reviewed content digest remain operator actions. The direct deployment and insertion CLIs are disabled; the wizard imports these functions after approval checks. |
| 3 | Installer runtime observations | Bundle generation and Docker image-load I/O now join the strict gate, alongside bundle verification, base Compose/image-inventory mappings, static portal archive, and runtime healthcheck decisions. Docker daemon identity and actual offline behavior still require independent deployment evidence; checked-JS is not that evidence. |
| 4 | `scripts/check-helm-image-mapping.mjs`, `scripts/observe-helm-runtime.mjs` | Optional Kubernetes mapping and observations; Helm is not a 0.1.0 RC gate. |
| 5 | Runtime egress observations beyond the dedicated API/ledger probes | Ledger topology, internal canary, disposable local positive/negative egress, API runtime identity, and API route probes join the strict gate. Host, wallet, browser, backup, and actual actor egress still require measured deployed evidence; checked-JS does not prove them. |
| 6 | `scripts/observe-standalone-qualification.mjs`, `scripts/check-standalone-current-query-journey.mjs`, `scripts/check-standalone-api-restart.mjs` | The aggregate's scope decision and current-query process-identity decision are strictly checked, but Docker/runtime probe I/O and report identity assembly remain non-strict. Keep exact-source, install, deployment, and container identity negatives while typing the remaining shells. |

The standalone acceptance inventory checker and its manifest-shape and
decision-chain policies now join the strict gate. Runtime tests still check
malformed candidate fields, missing cases, unsafe paths, evidence aliases,
private-file changes, and ordered operator verdicts. Typechecking and a
private hash-linked inventory do not authenticate a receipt, finality, a
reviewer, or the truth of an operator verdict; independent release review
remains necessary.

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
