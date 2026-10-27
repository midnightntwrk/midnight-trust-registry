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
As of 2026-10-27, #238's external Opengrep OSS check was red.
[Issue #237](https://github.com/midnightntwrk/midnight-trust-registry/issues/237)
tracks its disposition. Do not hide, waive, or mark the stack ready while
the five internal WebSocket transport findings or the PGP negative-test marker
remain unresolved.
The latter has a local test fix, but it does not clear the published check
until applied to the owning PR and rerun at its new head.

## Unpublished continuation

There are 51 signed/DCO local commits above #240's published head
`bbe527cf` through `c786254f`. They are **not published**, and publication
requires the user's separate approval. Preserve their existing order and
review them as four contiguous, context-sized diffs rather than opening one
PR per commit. Before any publication, fetch the live #240 head and check
that it is still the ancestor of the first group; do not force-push or
rewrite unpublished work to repair a stale base.

| Group | Local commit range | Proposed focus | Required review emphasis |
| --- | --- | --- | --- |
| A | `4bae0f32`..`31ef0672` | Durable applicant challenge state, duplicate-key quorum rejection, recovery reviewer and genesis/governance reviewer boundaries | Atomic issuance and consumption, replay, signer distinctness, no recovery waiver |
| B | `91c5a941`..`8fba8e05` | Static archive and Compose typing, verified v6 install and isolated egress canaries, predeployment evidence limits | Loaded-image identity, route isolation, DNS/TCP positive controls, no claim of actor or host egress |
| C | `aba60244`..`bc55a27d` | Genesis-pin and bundle preflight, safe prebuilt demo E2E, journal restart quarantine, operator/security handoff | Exact-source pinning, no destructive Compact rebuild, no simulator-to-deployment promotion, restart ambiguity |
| D | `50cbd1a5`..`c786254f` | Full-precision application, recognition, lifecycle, challenge, and TRQP evidence time decisions | RFC3339 offsets and long fractions, one-use nonce ordering, historical evidence selection; #179 remains open |

For a stacked publication, the first group would target #240, and each later
group would target the immediately preceding group. The table is a review
plan, **not** an authorization to push, create PRs, mark drafts ready, merge,
or claim exact-head CI. Verify GPG/DCO, focused and applicable full checks,
and independent current-head review for each group after publication. The
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
#238's unresolved external scan and #232's human security release gate remain
separate stop conditions.

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
