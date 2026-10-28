# Standalone Unpublished Review Groups

Status: local planning checkpoint, not publication or release approval.
The first 0.1.0 RC targets self-hosted local/offline runtime only. Preview,
Preprod, Mainnet, and Kubernetes are not RC qualification targets.

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
