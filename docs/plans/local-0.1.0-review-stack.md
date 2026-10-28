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

Further signed/DCO local slices are stacked above #240, including prebuilt
demo/E2E build safety, journal restart quarantine, and the real synthetic GPG
private-export negative test. They are **not published**. Inspect the live Git
graph and working-tree status before grouping or propagating them; never
rewrite or discard unpublished commits to make the stack appear clean.

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
