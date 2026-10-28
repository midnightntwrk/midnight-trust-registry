# Trust Registry Execution Backlog

Status: active
Updated: 2026-10-28

The [0.1.0 reference profile](../spec/milestone-0.1.0.md) is the product
contract. The [0.1.0 issue plan](milestone-0.1.0-issues.md) contains the
ordered, testable implementation slices and is the source of truth for milestone
acceptance. The first RC is **self-hosted local/offline runtime only**: install
may use the network, but the qualified runtime may not use external egress.
Preprod and other public networks, historical API/TRQP decisions, and
Kubernetes/Helm qualification are outside this RC. GitHub
[milestone 0.1.0](https://github.com/midnightntwrk/midnight-trust-registry/milestone/1)
tracks execution. The broad [v1 specification](../spec/trust-registry.md)
continues to describe the longer-term system. A simulator, mocked provider,
or self-attested wizard status is not deployed local-ledger evidence.

## Delivered Foundation

Merged on `develop` before this milestone plan:

- Domain models, lifecycle validators, canonical evidence bundle, Compact
  registry, maintainer membership, and scoped issuer/verifier/auditor and
  recognition records.
- Multi-maintainer quorum, governance policy templates, signed epoch records,
  simulator/client integration, DID resolution fixtures, VC status fixtures,
  TRQP and experimental OpenID Federation adapters.
- Local operator CLI, read/query API, mutable workspace API, applicant portal,
  admin console, demo, packaging, and repository quality workflows.
- [Application evidence specification](../spec/application-evidence.md),
  [ADR-0001](../decisions/adr-0001-governance-evidence-and-policy-snapshots.md),
  [ADR-0002](../decisions/adr-0002-resource-and-request-profile-canonicalization.md),
  and an initial on-chain application evidence hash binding.

These are components of a reference implementation, not proof that one real
VC/VP-backed application and authenticated HTTP governance journey works end
to end. Published DID/VC-backed intake and signed local HTTP mutations now
have focused tests, but they drive separate state paths: the intake reaches the
Compact simulator, while the HTTP gateway replays an operator workspace. The
local workspace's fixture maintainer is not a Compact-backed 2-of-3 approval
bundle. Combined VP/proposal HTTP hosts now require a receipt-backed admission
port. A deterministic local issuer journey now projects registration preflight
and public lookup from one Compact simulator and connects signed registration,
VP receipt, 2-of-3 governed transitions, and epoch-backed lookup. Applicant
records and accepted evidence now have a private file-backed local adapter,
but challenge consumption, receipt acceptance, and governance are not one
atomic transaction. A read-only resolution route recovers a lost submit
receipt for all four membership roles by matching admitted evidence to a
Compact proposal event, but `not-observed` cannot justify a retry. The next
functional slice must provide a deployable authoritative host and a finality-
aware handoff for uncertain submissions. The Compact contract
checks evidence hashes but does not itself resolve the evidence verifier's DID
assertion key.

## Current Local RC Critical Path

The [executable issue plan](milestone-0.1.0-issues.md) and
[operator acceptance cases](../guide/standalone-local-journey.md#operator-acceptance-record)
control the release decision. Draft implementation PRs #238-#240 provide
reviewable code and tests, not a qualified deployment. Promotion PR #198
remains draft. Do not convert a passing light, demo, browser-fixture, or
read-only observer test into an `A01`-`A04` actor verdict.

| Gate | Work still required | Release evidence |
| --- | --- | --- |
| Local ledger and approvals | [#219](https://github.com/midnightntwrk/midnight-trust-registry/issues/219), [#233](https://github.com/midnightntwrk/midnight-trust-registry/issues/233), [#234](https://github.com/midnightntwrk/midnight-trust-registry/issues/234) | One source-matched install, independently signed genesis and release committee, deployed contract, authenticated finalized constructor/authority/verifier-key readback, and signed API plan bound to those receipts. |
| Offline actor journeys | [#219](https://github.com/midnightntwrk/midnight-trust-registry/issues/219), [#90](https://github.com/midnightntwrk/midnight-trust-registry/issues/90) | Real local issuer, verifier, auditor, maintainer, recognition, and relying-party paths with a VC-owned live status-authority adapter, governed writes and current reads, plus host/container/wallet/browser/prover egress-denial evidence. The packaged signed-plan API CLI is still read-only. |
| Recovery | [#220](https://github.com/midnightntwrk/midnight-trust-registry/issues/220), [#230](https://github.com/midnightntwrk/midnight-trust-registry/issues/230) | Deployed restart and distinct-project restore, checkpoint continuity, durable ambiguous-attempt quarantine, and independently authenticated recovery disposition. Process and synthetic-snapshot tests are not deployed recovery. |
| Artifact and security review | [#236](https://github.com/midnightntwrk/midnight-trust-registry/issues/236), [#237](https://github.com/midnightntwrk/midnight-trust-registry/issues/237), [#232](https://github.com/midnightntwrk/midnight-trust-registry/issues/232) | Manifest-backed exact-source packages/images/proving keys, disposition of the red external scanner findings, and a non-author human review of the same candidate with signed findings and release-owner sign-off. A GPG verifier checks bytes, not reviewer independence or finding truth. |

Use the private `L01`-`S01` acceptance inventory to retain commands, receipts,
checkpoints, negative outcomes, and reviewer decisions for **one** candidate.
Its `allOperatorCasesPassed` field is a self-attested inventory result, not
release qualification; independent finality and security disposition remain
separate gates. The current-only API requires operator-reviewed re-signing and
a controlled restart after each governed mutation. Never publish wallet
material, private acceptance evidence, or generated proving secrets in a PR.

## Historical Functional Path

The following table records the earlier simulator and package implementation
plan. Its issue wording and statuses need reconciliation before closure. It is
not the current RC release sequence; #39 historical API/TRQP routes are
deferred, while #218 Helm is optional. The scoped issues above take precedence
for local runtime qualification.

The original order was DID/VC/VP intake and Compact-governed decisions
(#76, #67, #77), simulator-backed actor cases (#58, #78), API/UI/query and
adversarial cases (#59, #60), then VC consumer anchors (#79, #73). Those
tests remain useful regression coverage, but their issue status cannot be
read as proof of the deployed local runtime. #39 historical routes were in
that original order and are now deferred from this RC.

| Slice | Existing issue or planned issue | Exit evidence |
| --- | --- | --- |
| Specification and tracker reconciliation | [#49](https://github.com/midnightntwrk/midnight-trust-registry/issues/49) | Actor/use-case contract and milestone issue map pass docs validation. |
| Canonical scope and policy snapshots | [#75](https://github.com/midnightntwrk/midnight-trust-registry/issues/75) | One set of role-specific vectors across domain, contract wrapper, API, client, and adapters. |
| Real VC/VP evidence attestation | [#76](https://github.com/midnightntwrk/midnight-trust-registry/issues/76) | Official DID/VC packages validate applicant evidence and sign its commitment. |
| DID-bound on-chain attestation | [#67](https://github.com/midnightntwrk/midnight-trust-registry/issues/67) | Compact rejects fake, substituted, retired, or unauthorized assertion keys. |
| Authenticated mutation gateway | [#77](https://github.com/midnightntwrk/midnight-trust-registry/issues/77) | Applicant and maintainer intents are signed, scoped, and replay safe. |
| Historical public evidence | [#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39) | API and TRQP extension carry epoch, policy, scope, and verifiable proof at time T. |
| VC decision evidence | [#79](https://github.com/midnightntwrk/midnight-trust-registry/issues/79) | TR authenticates exact issuer/verifier grant, DID method/key, policy, and epoch before descriptor production. |
| Portable VC signer anchor | [#73](https://github.com/midnightntwrk/midnight-trust-registry/issues/73) | TR signs VC-compatible issuer/verifier descriptors; Ledger 8 consumer pins the authority and rejects replay/substitution. |
| Issuer trust journey | [#58](https://github.com/midnightntwrk/midnight-trust-registry/issues/58) | VC/VP -> quorum -> epoch -> accepted/rejected trust evaluation. |
| Other actor journeys | [#78](https://github.com/midnightntwrk/midnight-trust-registry/issues/78) | Verifier, auditor, recognition, and maintainer positive/negative E2E paths. |
| API/UI and adversarial journeys | [#59](https://github.com/midnightntwrk/midnight-trust-registry/issues/59), [#60](https://github.com/midnightntwrk/midnight-trust-registry/issues/60) | Public contracts preserve the same rules and fail closed under tampering. |
| Release candidate | [#45](https://github.com/midnightntwrk/midnight-trust-registry/issues/45) | Clean-checkout validation and digest-verified package/contract artifacts. |

## Historical First 20 Issues

The original issue tranche (#29-#48) is grouped by scope and original priority
for traceability. This table is historical; current 0.1.0 priority is the
critical path above. The "reconcile" status means merged implementation must
be checked against the issue's acceptance criteria before closure.

| Scope / priority | Issues | Tracker state |
| --- | --- | --- |
| Governance / P1 | [#29](https://github.com/midnightntwrk/midnight-trust-registry/issues/29), [#30](https://github.com/midnightntwrk/midnight-trust-registry/issues/30), [#31](https://github.com/midnightntwrk/midnight-trust-registry/issues/31) | Closed |
| Operator, API, UI / P2 | [#32](https://github.com/midnightntwrk/midnight-trust-registry/issues/32), [#33](https://github.com/midnightntwrk/midnight-trust-registry/issues/33), [#34](https://github.com/midnightntwrk/midnight-trust-registry/issues/34), [#35](https://github.com/midnightntwrk/midnight-trust-registry/issues/35), [#36](https://github.com/midnightntwrk/midnight-trust-registry/issues/36) | Closed |
| Historical queries and proof / P2 | [#37](https://github.com/midnightntwrk/midnight-trust-registry/issues/37), [#38](https://github.com/midnightntwrk/midnight-trust-registry/issues/38) closed; [#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39) open | #39 requires concrete historical API/TRQP evidence |
| Demo and packaging / P2 | [#40](https://github.com/midnightntwrk/midnight-trust-registry/issues/40), [#41](https://github.com/midnightntwrk/midnight-trust-registry/issues/41), [#42](https://github.com/midnightntwrk/midnight-trust-registry/issues/42), [#43](https://github.com/midnightntwrk/midnight-trust-registry/issues/43), [#44](https://github.com/midnightntwrk/midnight-trust-registry/issues/44), [#45](https://github.com/midnightntwrk/midnight-trust-registry/issues/45) | Open; #40-#44 reconcile, #45 is 0.1 gate |
| Public repository / P1 | [#46](https://github.com/midnightntwrk/midnight-trust-registry/issues/46) | Closed |
| Publication and dependency refresh / P2 | [#47](https://github.com/midnightntwrk/midnight-trust-registry/issues/47), [#48](https://github.com/midnightntwrk/midnight-trust-registry/issues/48) | Open; reconcile |

## Deferred And Reconciliation Queue

- Ledger 8 synchronous cross-contract calls and production relayer monitoring
  remain outside the reference milestone; #73 delivers portable descriptors
  and a locally pinned consumer fixture without requiring either capability.
- [#61](https://github.com/midnightntwrk/midnight-trust-registry/issues/61)
  through [#64](https://github.com/midnightntwrk/midnight-trust-registry/issues/64):
  dependency automation, public docs site, change-aware CI, and additional
  boundary automation stay open but do not block the reference profile.
- [#40](https://github.com/midnightntwrk/midnight-trust-registry/issues/40)
  through [#44](https://github.com/midnightntwrk/midnight-trust-registry/issues/44),
  [#47](https://github.com/midnightntwrk/midnight-trust-registry/issues/47),
  and [#48](https://github.com/midnightntwrk/midnight-trust-registry/issues/48):
  reconcile each acceptance criterion against merged PR #71. If implemented,
  close with a comment naming PR, merge commit, validation command, and any
  deliberate deferral. Do not close [#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39)
  without a concrete implementation reference for historical API/TRQP output.

## Legacy Backlog Aliases

Older decision notes still refer to `TR-026` (mutable operator CLI, now #32),
`TR-027` (read/query and applicant APIs, now #33 and #34), and `TR-029`
(historical query/proof/adapters, now #37, #38, and #39). These are historical
labels, not additional open work items.

## Delivery Rule

Each code PR links its issue, contains DCO/GPG-signed commits, updates the
relevant spec/ADR when behavior changes, includes positive and negative tests,
and runs `./run.sh --light`. Integration or E2E slices additionally run
`./run.sh integration`; release/demo slices run `pnpm run demo:smoke` and packed
artifact smoke checks. A merged issue is closed only with its implementation
reference and validation evidence.
