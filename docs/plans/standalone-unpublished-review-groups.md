# Standalone Unpublished Review Groups

Status: local planning checkpoint, not publication or release approval.
The first 0.1.0 RC targets self-hosted local/offline runtime only. Preview,
Preprod, Mainnet, and Kubernetes are not RC qualification targets.

## Local live-#240 review stack (2026-10-28)

Four **unpublished** signed/DCO branch heads now form a direct ancestry chain
above the live draft #240 head `8dc05ec7`. The original unpublished branch
`codex/trust-registry-unpublished-stack-restack` remains untouched at
`aee87db2`; the final review branch had the same tracked tree at
`78d0c624` before this documentation update. No new PR was opened.

| Proposed review PR | Local branch and tested head | Parent | Scope and local validation |
| --- | --- | --- | --- |
| Local operator core | `codex/trust-registry-review-live240-core` (`f7d2efa9`) | Draft #240 | 92 topology tests, docs check, audit. |
| Qualification and recovery | `codex/trust-registry-review-live240-qualification` (`caaec744`) | Local operator core | 97 topology tests, docs check, audit. |
| Adoption and evidence | `codex/trust-registry-review-live240-adoption` (`d8179c82`) | Qualification and recovery | 111 topology tests, docs check, audit; merge retained the inode guard and private-file fixture requirements from live #240. |
| Final security and E2E hardening | `codex/trust-registry-review-live240-final` (read the live tip; full-suite checkpoint `78d0c624`) | Adoption and evidence | 121 topology tests, 290 API unit tests, typecheck, docs check, audit, four simulator-backed membership journeys, CLI/API/UI fixture smoke, and 11 Playwright fixture-browser cases at the checkpoint. Later commits clarify this handoff, reject portable archive-path aliases, add a real-journal under-threshold regression, and test direct WebSocket denial; API light passed 345/345 and the expanded fixture browser suite passed 12/12. |

Issue #241 has a separate **local-only, non-rewriting** propagation chain.
It starts with signed/DCO `271ad6cd` on the exact published #238 head,
then signed/DCO merge candidates `7be83bc9` for #239 and `d162d0e0` for #240.
The original published PR heads and four local review-group branches above
remain unchanged. The review-group candidates are:

| Local candidate | Pre-handoff head | Parent candidate | Focused validation |
| --- | --- | --- | --- |
| `codex/trust-registry-review-core-with-241` | `4cafc321` | #240 candidate `d162d0e0` | Wizard/exact-field 105/105, strict type gate, docs, audit. |
| `codex/trust-registry-review-qualification-with-241` | `11b9ef60` | Core candidate | Wizard/exact-field 111/111, strict type gate, docs, audit. |
| `codex/trust-registry-review-adoption-with-241` | `b88a7aee` | Qualification candidate | Wizard/exact-field 111/111, strict type gate, docs, audit. |
| `codex/trust-registry-review-final-with-241` | `52e2b87c` | Adoption candidate | Wizard and three policy suites 115/115, both security-script type gates, docs, audit. |

The final candidate keeps one exact-field implementation and a separate
canonical signed-byte parser. These checks are local, not exact-head CI or
deployed standalone evidence. No candidate was pushed; obtain explicit push
approval, then recheck live parent heads and run exact-head CI and review.
Issue #241 is not a waiver for #237, #232, or the operator release gates.

Two further **unpublished** signed/DCO commits form a direct local chain above
the final candidate and do not change published PR heads:

| Local branch | Code checkpoint | Scope and evidence |
| --- | --- | --- |
| `codex/trust-registry-exact-fields-boundaries` | `e1e035b1` | Delimiter-safe genesis pin/review, deployment/insertion plans, signed wizard approvals and key insertions, and release committee checks. Wizard/packet 111/111, focused policy 10/10, strict typecheck, docs, and audit passed. |
| `codex/trust-registry-profile-field-validation` | `7ef4ebea` | Internal set-equality helper for network-profile and verifier-key catalogs. Package typecheck and lint, 34 focused tests, docs, and audit passed. |

A read-only Codex CLI review of the cumulative diff from `5265bd03` to
`7ef4ebea` found no actionable regression. This is not a non-author human
security verdict, exact-head hosted CI, or deployed E2E evidence. At the
live published #238 head `97e59c5e`, Opengrep OSS remains red on five internal
plaintext WebSocket findings; the aggregate scan is green. Issue #237 and
human review #232 require a real risk disposition, not a scanner waiver by
follow-up issue. No local branch was pushed or merged.

The validation above is local and scoped, not exact-head CI or independent
review. The final fixture E2E lane is not a deployed-ledger actor journey.
In this review checkout, `pnpm run test:standalone-topology` passes 121/121,
but `pnpm run contract:check-full-artifacts` stops because
`dist/managed/trust-registry/compiler/contract-info.json` is absent.
Consequently `pnpm run integration:prebuilt` was not run here. Do not copy
unverified generated output from another checkout or run a destructive
Compact rebuild in an artifact-bearing checkout to fill this gap; exact-head
CI or a separately verified, source-matched full-artifact lane must provide
that evidence.
Before publishing, confirm the live parent heads, run any missing full-light
and package checks without destroying artifact-bearing checkouts, obtain
independent exact-head review, and retain #238's external scanner failure as
an unresolved security disposition under #237/#232. Do not merge or promote
#198 on the strength of this stack.

## Release-gate handoff

The following work cannot be inferred from the passing local test lanes. Keep
each gate open until an operator records evidence against one exact source,
install inventory, genesis, contract address, and signed API plan. The
[operator acceptance record](../guide/standalone-local-journey.md#operator-acceptance-record)
defines the case IDs and required raw receipts.

| Gate | Who must act | Stop condition |
| --- | --- | --- |
| Approved local chain and committee | Independent operator and governance key holders | Node-reported genesis or a development 1-of-3 roster is not approval. The operator must review real chain-spec evidence and sign the exact approval bytes; governance must approve the release roster and custody roles. |
| Finalized deployment and current reads | Funded local-ledger operator | Pre-deployment bridge continuity and simulator results do not authenticate finality or read back a deployed contract and all verifier keys. |
| Live actor and offline journeys | Deployment integrator and operator | The packaged API CLI is read-only. Approved provider code, governed-write ports, a VC-owned live status authority, and egress-denied actor receipts are still required. |
| Recovery and security disposition | Backup operator and non-author human reviewer | API restart probes are not distinct-project deployed restore. Issue #232 requires a human verdict, and #237 requires disposition of the external scan before release. |

The operator can run fixture tests and inspect this stack now, but must not
record any `L01`-`S01` acceptance case as passed from those results. A signed
genesis approval or security verdict is a human action; do not generate either
on the reviewer's behalf. Kubernetes and public-network deployment are not
part of this local 0.1.0 RC gate.

## Why Group the Work

The clean local restack at `7af8e72d04ca3799658aaa90d87b133542711494`
contains about 212 first-parent commits and roughly 10,000 added lines beyond
the historical #240 base. Publishing that as one PR would obscure the
security, recovery, and adoption boundaries. These are **proposed** review
groups, not independently tested PR heads:

| Group | Historical range | Review focus |
| --- | --- | --- |
| Local operator qualification | `bbe527cfd70394cef5ba5225cc6600368028b3a4..d3b2d2019e39b562d932c93436d8c5130eedea5b` | Challenge state, applicant issuance, durable writes, reviewer recovery, typed archives, Compose egress policy, genesis pin validation, and installed-bundle checks. |
| Approval and recovery security | `d3b2d2019e39b562d932c93436d8c5130eedea5b..d02fcb0186d3b5966648b5b37df59ef3a7b0a10a` | Current-query identity, approval consistency, adversarial replay, strict GPG validation, security verdicts, status timing, and recovery tombstones. |
| Adoption and E2E evidence | `d02fcb0186d3b5966648b5b37df59ef3a7b0a10a..7af8e72d04ca3799658aaa90d87b133542711494` | Fixture browser journeys, adversarial matrix, transport assumptions, publication manifest, verifier-key catalog, and source-bound observations. |

The ranges above begin on the **old** #240 base. Before publication, restack
each group onto the live parent PR head without rewriting or discarding the
original unpublished branch. Check file and commit ownership at each boundary,
run focused tests and audit, obtain an independent exact-head review, and run
the applicable CI/full-light lane on each exact PR head. Keep signed/DCO
commits and preserve all generated keys, bundles, private approval packets,
and ledger volumes. Do not publish merely because this plan exists.
The later local trust-anchor loader commit `59cc8b85` belongs with the
approval and recovery security review, but its original stack position must
be preserved until a safe, reviewed restack is planned. These historical
group ranges do not include that commit.

## Evidence Boundary

At the local `7af8e72d` checkpoint, the fixture browser lane passed four
simulator-backed role journeys, fixture CLI/API/UI smoke, and 11 Playwright
tests. The full adversarial inventory check reported 198 demo cases and 198
isolated cases with no missing IDs. Neither result is a deployed standalone
end-to-end test. A real local RC still needs human-signed genesis and release
committee approval, authenticated finalized deployment/readback, a VC-owned
live status authority, egress-denied actor journeys, deployed restart/restore,
and independent human security review. Keep promotion PR #198 draft.

The external Opengrep OSS check on draft #238 remains red for internal
plaintext WebSocket findings. Issue #237 requires a human security disposition;
the aggregate scan or this local evidence cannot waive that gate. Drafts
#238, #239, and #240 must not be merged until their applicable checks and
review gates are satisfied and merge is explicitly authorized.
