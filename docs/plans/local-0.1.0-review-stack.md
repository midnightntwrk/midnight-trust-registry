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
On 2026-10-28, #238's live head was `5b6d2851`, but #239's recorded base
commit was still the earlier #238 head `53ce87c9`; #239 and #240 heads
remained `b723a84b` and `bbe527cf`. A read-only merge-tree calculation of
the current #238 and #239 heads found no textual conflict. It did not update
either PR or validate the combined tree. Before progressing the queue, safely
integrate #238's branch-owned changes into #239 and then #240, without
rewriting unpublished work; rerun applicable exact-head CI and review on
each updated PR. Do not publish local continuation groups onto a stale top
head, and do not mark #238 ready while its external scan is unresolved.
Local-only integration completed on 2026-10-28: signed/DCO merge `04d5e37d`
combines the current #238 head with #239, and signed/DCO merge `cc7c081b`
combines that result with #240. Both combined trees passed 117 focused setup
and acceptance tests, docs checks, dependency audit, and `./run.sh --light`
(20/20 tasks); read-only Codex reviews found no actionable merge regression.
The #240 tree also passed 198/198 adversarial parity and packed consumer smoke.
Signed/DCO merge `b29a1d65` brings this restacked ancestry under the local
unpublished continuation without changing its file tree. These local branches
have not been pushed, so the published PRs still have stale heads and must run
their own exact-head CI and review if publication is approved. None of these
tests is a deployed standalone actor journey or an external scan disposition.
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

### Consolidated local review candidates (2026-10-28)

The unpublished signed/DCO commits above published #240 head `bbe527cf` have three
non-rewritten original group boundaries and a post-restack continuation below.
These are review candidates,
not published PRs or a release verdict. Recheck the live #240 head and the
applicable CI/security disposition before publishing any of them.

| Order | Local branch | Range above base | Review context |
| --- | --- | --- | --- |
| 1 | `codex/trust-registry-review-group-core` (`c786254f`) | 51 commits; `bbe527cf`..`c786254f` | Durable challenge and quorum preflight, verified install/egress canaries, safe demo build, journal restart, full-precision trust times |
| 2 | `codex/trust-registry-review-group-qualification` (`723df991`) | 42 commits; `c786254f`..`723df991` | Approved-setup/current-query binding, read-only recovery candidate, acceptance evidence integrity, scoped qualification observations, retained approval checks |
| 3 | `codex/trust-registry-signed-evidence-type-gate` (`674160e4`) | `723df991`..`674160e4` | Isolated policy/adversarial cases, strict standalone script boundaries, audited proposal tombstones, signed security verdict, observation ambiguity, operator handoff, and signed status-time regression coverage |

Local-only restacked review refs now preserve the original group tips and
commit history: `codex/trust-registry-review-group-core-restacked-local`
(`67212c1e`) descends from the validated #240 restack `cc7c081b`;
`codex/trust-registry-review-group-qualification-restacked-local`
(`a2d4c2a2`) descends from that core ref; and
`codex/trust-registry-review-group-adoption-restacked-local` initially reached
`506537e0` above the qualification ref. All three merge commits are GPG-signed
and DCO-signed. The core merge added the #238 acceptance-path alias fix and
its 15 focused acceptance tests passed. The later two merges changed no file
content relative to their first parents; the adoption tree had previously
passed the full light, fixture E2E, and browser gates. These refs are not
published. Recheck live remote heads and run exact-head CI and review after
any approved push; local ancestry and tests do not clear #238's external scan
or the local release evidence gates.

The next local review boundary is
`codex/trust-registry-review-group-e2e-knowledge`, stacked above the
restacked adoption ref `506537e0`. Its range contains 16 prior commits plus
the handoff update, a parity-runner correction, and this review note:
fail-closed query evidence, isolated policy/public lookup
and temporal demo cases, complete adversarial report attribution, a browser
fixture egress audit with redirect denial, checked standalone current-query
inputs, and a reproducible pinned-Chromium adoption path. Writable local
validation on the continuation passed both browser variants (11/11), 198/198
adversarial parity, `./run.sh --light` (20/20 tasks), the security script type
gates, and `pnpm audit --audit-level low`. A whole-range Codex review found
two parity-runner edge cases; commit `f47da625` rejects empty isolated coverage
and malformed demo cases with new negative tests. The corrected whole-range
review found no actionable regression. Review the **whole** range again at
its exact published head before merge; these local checks are not
deployed standalone actor evidence, current-head PR CI, or a disposition of
#238's red external Opengrep check.

On 2026-10-28, read-only Codex CLI reviewed each complete restacked group
against its local parent (`cc7c081b` to `67212c1e`, `67212c1e` to
`a2d4c2a2`, and `a2d4c2a2` to `506537e0`). No actionable regression was
reported. The reviewer sandbox could not create temporary directories for
filesystem-dependent tests; a separate writable run at the adoption head
passed 136 focused acceptance, security-verdict, egress, and wizard tests.
The documentation check and `pnpm audit --audit-level low` passed there too.
This review and test evidence does not clear #238's external scan, replace
exact-head PR CI, or prove deployed standalone actor journeys.
Later signed/DCO local commits recorded that review, hardened aggregate
current-query evidence shape, and extracted the policy-revision/atomic-recovery
fixture scenario under #216. The latter retained six case IDs, passed the
governed demo, 198/198 adversarial parity, 240 isolated demo-smoke tests,
`./run.sh --light` (20/20 tasks), and dependency audit. Its exact-commit
read-only Codex review at `9dbbffad` found no actionable regression. The
governed demo remains sequential and these cases are not deployed-ledger E2E.

The top group passed a local full light gate (20/20), focused wizard and
security-signature tests, strict security-boundary typecheck, docs check, and
dependency audit at `76487e16`; a read-only Codex commit review found no
actionable regression. These tests use fixtures or pre-deployment observations.
They are **not** deployed standalone actor E2E, authenticated finality, an
independent human security verdict, or exact-head GitHub CI. No new group has
publication or merge authorization. Keep #198 draft and preserve private
setup evidence, generated Compact artifacts, and ledger volumes.
The subsequent status-time extension verifies a fixture-signed response through
an actual loopback HTTP listener and the VP intake, including a fractionally
overlong rejection. At local tip `97480807`, the integration suite passed
354 tests with two skipped; typecheck, lint, docs, and audit passed. The last
full light gate passed 20/20 at the preceding runtime-code tip `e55cb4e3`;
later commits changed only tests and docs. The loopback test is transport
coverage, not a VC-owned live status adapter or deployed-ledger actor case.
The subsequent local recovery race fixes through `88f46da4` preserve signed
abandonment tombstones when reconciliation or a provider receipt completes
after abandonment, including after journal rotation. A null finalized read
now refreshes the journal before returning rather than exposing a stale
reservation. Focused journal tests passed 39/39, API typecheck/lint, docs
check, and dependency audit passed; the full light gate passed 20/20 at the
code tip. Exact-commit read-only reviews found no actionable regression.
These interleavings use fixture readers, not an authenticated finality source
or deployed recovery evidence.
The current-query observer's report decisions were then extracted into a
strictly checked policy at local `1106d749`. Its 11 focused journey tests,
strict security-boundary typecheck, docs check, audit, and full light gate
(20/20) passed; exact-commit read-only review found no actionable regression.
The Docker/runtime probe orchestration is still not strictly typed, and the
tests remain injected-provider evidence rather than a deployed actor run.

The local descendant contains the reviewed groups A-D above #240's published
head `bbe527cf`, followed by review-plan documentation, current-query
approval-binding group E, a read-only ambiguous-recovery group F, and an
adversarial-report hardening group G, and local-profile/qualification-docs
group H, observation-scope guard group I, typed scope-policy group J, and
current-query process-identity group K, retained-approval consistency group L,
and recovery-handoff alignment group M. They are
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
| L | `24dd5acd` onward | Reject corrupted or setup-inconsistent retained genesis, roster, and deployment-bound committee approval evidence; expose an invalid status instead of a verified label | Retained-byte checks do not replace independent GPG trust-anchor verification, signed real chain-spec review, or deployed E2E |
| M | `8eaf194a` onward | Align operator recovery guidance with the implemented v3 candidate and distinct-reviewer signed decision | The decision verifier does not authenticate finality or release a reservation; #220 and deployed recovery remain open |

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
the branch-owned fixes now published on #238. The local ancestry-only merge
above reconciles those equivalent patches without a duplicate file change;
do not force-push or claim deployed E2E from these tests.
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
application-evidence cases to named fixture modules. A later local slice
also moved six recognition-intake rejection cases to a named scenario module;
its six isolated tests, governed demo, and exact 198/198 case-ID parity pass.
The adjacent recognition challenge, accreditation, scope-substitution, and
proposal fixture flow now lives in a separate module while returning the same
verified evidence and event hash to the demo; the governed demo and case-ID
parity still pass after that move.
Issuer, verifier, and recognition consumer-evidence fixture checks now run
through a named module as well, including the existing tampered Merkle path,
wrong resource scope, and recognition-as-issuer rejection cases. This is
fixture/API-client coverage, not a deployed standalone relying-party run.
The verifier, auditor, and maintainer proposal fixture loop is separately
isolated with its quorum and evidence/scope-substitution cases beside each
successful proposal and observed receipt. This still uses the simulator-backed
demo; it is not a deployed actor submission or authenticated finality proof.
The four maintainer-safety cases now use separate simulator fixtures and run
as named Node tests in the demo-smoke gate. Their post-rejection ledger
invariants are part of each recorded outcome; a deliberately bad signer test
shows later cases still run. The demo-smoke suite passed 240/240, the governed
demo passed, and exact adversarial case-ID parity remained 198/198. This is
fixture regression coverage only, not an on-ledger actor qualification.
At signed/DCO local head `17f026de`, `pnpm run test:e2e:demo` passed the
prebuilt Compact, four signed role journeys, API/CLI, and served-UI smoke
lanes. `pnpm exec playwright test` separately passed 10/10 Chrome browser
cases, including applicant flows and lost-response recovery. These are
fixture-backed adoption checks; they do not establish a deployed local
contract, authenticated finality, live VC status, or egress-denied actor work.
These refactors harden report integrity and advance the remaining #216 demo
extraction, but do not finish that issue or
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

On 2026-10-28, the read-only journey-prerequisite checker was run against the
retained private `wizard-b23` setup at its recorded source revision
`6a5b2529baf39e0a6ac2b63be2fa4a848fec2175`. It confirmed that the
install was staged and the dedicated pre-deployment stack observed, but
returned exit code 2 with `genesisApproved` as the first missing gate.
Release-roster approval, deployment/readback, verifier-key reconciliation,
and maintenance transition were also absent. This setup is older than the
unpublished review stack and is not a current-source qualification candidate.
Do not rerun deployment against it or use its node-reported genesis proposal
as independent approval. The next release run needs a fresh exact-source
bundle and human-signed real genesis and roster evidence before any actor E2E
case can begin.

Group L's local wizard and journey-prerequisite tests passed 120/120 after
its retained-evidence checks. Strict security-script typing, docs checks,
and dependency audit passed. A read-only Codex review identified two status
gaps for the deployment-bound approval (manifest digest and missing roster);
both were fixed, and a second read-only review found no further actionable
regression. The reviewer sandbox could not create test fixtures, so these
test results are from the separate writable local run. Neither review nor
fixture test authenticates a human signature or qualifies a deployed ledger.
