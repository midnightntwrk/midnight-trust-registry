# Local 0.1.0 review stack

The first release candidate targets a self-hosted local Midnight ledger with
offline runtime. Preview, Preprod, Mainnet, and Kubernetes are not qualification
gates. Keep [promotion PR #198](https://github.com/midnightntwrk/midnight-trust-registry/pull/198)
draft until its scope and release gates are explicitly updated.

## Published draft stack

Review these PRs bottom-up. Query their **live exact heads** before every
review, CI decision, or retarget; the local unpublished descendants are not
part of their current diffs.

| Order | PR | Base | Focus |
| --- | --- | --- | --- |
| 1 | [#238](https://github.com/midnightntwrk/midnight-trust-registry/pull/238) | `milestone-0.1.0` | Local qualification core, pinned install, genesis and committee approval, provider and deployment boundaries |
| 2 | [#239](https://github.com/midnightntwrk/midnight-trust-registry/pull/239) | #238 head | Governed actor handoff, journal quarantine, signed API plan, recovery evidence |
| 3 | [#240](https://github.com/midnightntwrk/midnight-trust-registry/pull/240) | #239 head | Installer and operator adoption guide, acceptance evidence, fixture and pre-deployment checks |

The published PRs are draft. Check required CI and review at each exact head;
the top branch's local tests cannot substitute for the lower PRs' checks.
At signed/DCO head `5b6d2851` on 2026-10-27, #238's external Opengrep
OSS check remained red.
[Issue #237](https://github.com/midnightntwrk/midnight-trust-registry/issues/237)
tracks its disposition. Do not hide, waive, or mark the stack ready while
the five internal WebSocket transport findings remain unresolved. The earlier
incomplete PGP negative-test marker was replaced by a generated synthetic
private export on #238; the later exact-head external scan reported no PGP
annotation. That fix does not disposition the WebSocket transport risk or the
independent human security gate #232. The same #238 head also rejects case and
Unicode-normalized aliases of private acceptance evidence paths. Its focused
exact-tree tests and read-only Codex delta review found no actionable
regression. Full exact-head build/package/test, quality, docs, and aggregate
scan checks subsequently passed; external Opengrep remained red, so this is
not a fully green merge gate or release approval.

## Unpublished continuation

The local descendant contains the reviewed groups A-D above #240's published
head `bbe527cf`, followed by review-plan documentation, current-query
approval-binding group E, a read-only ambiguous-recovery group F, and an
adversarial-report hardening group G, and local-profile/qualification-docs
group H, observation-scope guard group I, typed scope-policy group J, and
current-query process-identity group K. They are
**not published**, and publication requires the user's separate approval. Preserve
their existing order and review them as context-sized diffs rather than
opening one PR per commit. Before any publication, fetch the live #240 head and check
that it is still the ancestor of the first group; do not force-push or
rewrite unpublished work to repair a stale base.

| Group | Local commit range | Proposed focus | Required review emphasis |
| --- | --- | --- | --- |
| A | `4bae0f32`..`31ef0672` | Durable applicant challenge state, duplicate-key quorum rejection, recovery reviewer and genesis/governance reviewer boundaries | Atomic issuance and consumption, replay, signer distinctness, no recovery waiver |
| B | `91c5a941`..`8fba8e05` | Static archive and Compose typing, verified v6 install and isolated egress canaries, predeployment evidence limits | Loaded-image identity, route isolation, DNS/TCP positive controls, no claim of actor or host egress |
| C | `aba60244`..`bc55a27d` | Genesis-pin and bundle preflight, safe prebuilt demo E2E, journal restart quarantine, operator/security handoff | Exact-source pinning, no destructive Compact rebuild, no simulator-to-deployment promotion, restart ambiguity |
| D | `50cbd1a5`..`c786254f` | Full-precision application, recognition, lifecycle, challenge, and TRQP evidence time decisions | RFC3339 offsets and long fractions, one-use nonce ordering, historical evidence selection; #179 remains open |
| E | `8ea73b91` onward (after review-plan docs) | Bind the standalone read-only current-query probe to wizard-approved install inventory, project, network, genesis, and deployment | Reject cross-setup or cross-deployment evidence before egress; no claim of actor writes or independent finality |
| F | `90eda72b`..`7a472176` | Prove the stale-sequence Compact invariant and bind a read-only recovery candidate to one immediately consumed action | An authenticated finalized action history and safe journal mutator are still absent; never treat a signed review decision as retry permission |
| G | `7626be30` onward | Reject interrupted adversarial reports and move independent maintainer, denial, and application-evidence safety scenarios out of the monolithic demo | Preserve 198-case demo/isolated parity; fixture cases are not deployed-ledger E2E |
| H | `e4fceb5b` onward | Use the standalone catalog identity in local finalized readers and clarify operator-node versus independently authenticated finality in the quickstart | Keep the per-installation genesis pin and signed approval gate; profile selection alone is not a deployed or independently finalized E2E result |
| I | `be2f3cb0` onward | Reject aggregate qualification reports whose child probes imply actor, finality, host/browser egress, or deployment-binding evidence they did not collect | Keep the observer read-only and `releaseQualified: false`; no fixture report substitutes for a signed deployed-ledger run |
| J | `9044f4d4` onward | Strictly check the pure qualification scope decision and reject malformed/missing child report fields | Remaining probe I/O is non-strict; typed scope checks are not independently authenticated finality or deployed E2E |
| K | `9f9ff560` onward | Require valid API container/process identity on both current reads around the egress probe, with strict checked-JS and negative tests | This is read-only observer assurance, not a deployed governed actor journey |

For a stacked publication, the first group would target #240, and each later
group would target the immediately preceding group. The table is a review
plan, **not** an authorization to push, create PRs, mark drafts ready, merge,
or claim exact-head CI. Verify GPG/DCO, focused and applicable full checks,
and independent current-head review for each group after publication. The
live #240 head was still `bbe527cf` on 2026-10-27. At local head `aaaeec39`,
all six group endpoints were in its descendant chain, and all 72 local
commits above it had good Git signatures and DCO trailers. This point-in-time
local audit does not replace a new base/identity check before publication. The
read-only local Codex review through `c786254f` found no actionable
regression in group D, but later commits or PR rebases require a fresh review.
Read-only Codex CLI reviews of group A at `31ef0672`, group B at
`8fba8e05`, and group C at `bc55a27d` also reported no actionable
regressions. Group B's reviewer ran focused egress/image-policy tests and
the strict security-boundary typecheck. Group C's reviewer could not run
temporary-file tests in its read-only sandbox, so a separate writable run at
that exact local endpoint passed 41 install, acceptance, journey-prerequisite,
and writer-review tests plus `test:e2e:demo`. Those results are fixture and
predeployment checks, **not** installed-ledger actor E2E, authenticated
finality, or a human security verdict. PR publication or changed heads still
require fresh applicable CI and review.
Read-only Codex CLI review of group E through `c0d15413` found no actionable
regression. A later review of the inventory-binding addition found two real
gaps: the reported digest came only from the supplied bundle, not the signed
API plan, and saved acceptance evidence did not bind its nested digest fields.
Both were fixed by `8b0fe879`; a second read-only review of that exact code
found no actionable regression. The local standalone topology suite passed
92 tests, 19 focused API tests and API typecheck passed after rebuilding the
domain package, and docs, security-boundary typecheck, and dependency audit
passed. These are predeployment checks only. A published PR still requires
fresh exact-head CI and review.
At local head `012d50b5`, a separate read-only Claude CLI review of group E's
current-query and acceptance changes found no actionable regression. The
standalone topology suite passed 92 tests and the local-ledger preflight suite
passed 215 tests at that head. Both are local predeployment suites; neither
authenticates a deployed actor journey or replaces current-head PR CI.
#238's unresolved external scan and #232's human security release gate remain
separate stop conditions.
Group F's v3 candidate includes the observed last-action kind and payload
hash and marks later or same-payload history inconclusive. Focused API tests,
typecheck, docs check, and audit passed locally; the read-only review found no
blocker after the last-action values were bound into the signed decision.
The later local acceptance-evidence alias and operator-guide commits overlap
the branch-owned fixes now published on #238. Reconcile those equivalent
patches when preparing any subsequent stack update; do not force-push,
duplicate their effect, or claim deployed E2E from these tests.
At local head `aaaeec39`, the acceptance and journey-prerequisite focused
tests passed 25/25, `pnpm run docs-check` passed, and
`pnpm audit --audit-level low` found no known vulnerabilities. The
[security-scan disposition](../guide/security-scan-disposition.md) now records
the exact Compose bridge membership and host-loopback node RPC exposure for
the five remaining WebSocket findings. This is a review input, not a scanner
waiver: #238 remains draft with external Opengrep OSS red, and #232 requires
an independent human disposition of the observed transport boundary.
The new local group G starts above F at signed/DCO commit `7626be30`.
Its runner regression tests passed 6/6 and the full isolated report completed
198/198 cases. The next local refactors moved nine maintainer, denial, and
application-evidence cases to named fixture modules; the governed demo and
exact 198/198 case-ID parity still pass. This hardens report integrity and
begins the remaining #216 demo extraction, but does not finish that issue or
qualify a deployed actor journey. Hold group G
locally until it is a coherent review-sized slice and publication is approved.

## Release boundary

The [operator journey](../guide/standalone-local-journey.md) defines the real
local-ledger acceptance cases. The
[security-review handoff](local-0.1.0-security-review-handoff.md) lists exact
review inputs and stop conditions; [human review issue #232](https://github.com/midnightntwrk/midnight-trust-registry/issues/232)
records the independent verdict. Neither a merged implementation stack nor
green simulator, browser, or packed-consumer tests closes that release gate.

The retained local-ledger observations are pre-deployment and bound to older
source revisions. A new exact-source install, independently reviewed and
human-signed genesis, approved release maintenance roster, authenticated
finalized deployment and readback, egress-denied actor journeys, deployed
restart and restore, VC-owned live status authority, and independent review
remain outstanding. Preserve generated Compact keys, verified install bundles,
private setup evidence, and ledger volumes while preparing those runs.
