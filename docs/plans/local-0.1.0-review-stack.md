# Local 0.1.0 review stack

This plan defines the grouped draft pull-request stack for the self-hosted,
local-only first release candidate. Public Preview,
Preprod, and Mainnet qualification is deferred. Helm is optional and must not
block the local RC. Keep #198 draft until its scope and release gates are
explicitly updated. Do not merge any branch solely because it appears in this
list.

Open the following branches bottom-up. Each PR targets the preceding row's
branch; row 1 targets `milestone-0.1.0`. The existing linear history is
retained, so no signed commits need rewriting. The abbreviated SHAs are
verification hints; review and CI must use exact remote heads.

| Order | Head branch | Local head | Review focus |
| --- | --- | --- | --- |
| 1 | `codex/trust-registry-rc-foundation` | `fc5fc34` | Release manifest, adversarial isolation, nonce capacity, canonical governance bundles, DID/VP security boundaries |
| 2 | `codex/trust-registry-standalone-setup-wizard` | `0d6e791` | Local deployment/finality path, pinned offline install, isolated ledger stack, resumable first-run wizard |
| 3 | `codex/trust-registry-rc-standalone-installer` | `49df9f9` | Reviewer-signed genesis, staged verifier keys, deployment-bound committee, maintenance journals, verified topology and restart observation |
| 4 | `codex/trust-registry-reviewer-public-key-export` | `319cf87` | Signed read-only API, pinned API/portal images, install relay, predeployment restart/restore, optional Helm and egress probes |
| 5 | `codex/trust-registry-helm-api-plan-binding` | `33c9395` | Signed approval and release-manifest hardening, current-only API plan, packed release identity and runtime binding |
| 6 | `codex/trust-registry-rc-current-plan-expiry-verified` | `5079a57` | Finalized current reads, journaled issuer proposals, pinned submission, ambiguous-outcome quarantine and recovery inspection |
| 7 | `codex/trust-registry-package-export-policy` | Resolve exact head | Offline API and egress observations, portal/admin/applicant current-state reads, signed recovery, network profiles and package export policy |

## Publication gates

- Recheck that each branch head is still the intended descendant of its
  proposed base before publication or review.
- Run required validation and independent exact-head review for each PR;
  local tests at the top of the stack do not substitute for each PR's CI.
- Preserve the verified install bundles, generated Compact keys, private
  setup evidence and active ledger volumes. Do not run destructive light/full
  build targets in the artifact-bearing checkout.
- Keep #198 draft. No row proves release readiness or authorizes a public
  deployment. The current exact-source install bundle predates the final row.

## Gates still open after code review

The operator must review the real local chain specification/genesis and sign
the exact first-run approval bytes. A node-reported candidate or synthetic
demo reference is not that approval. The approved release committee threshold,
public keys and custody roles also require human selection; 1-of-3 is smoke
only. Deployment must then produce a real finalized contract readback and an
approved maintenance transition. The API plan must be reviewed and signed for
that deployment. Egress-denied actor journeys, deployed restart and distinct-
project restore, a VC-owned live status-authority adapter, and independent
security review are not closed by simulator, mocked-provider, or predeployment
tests. Rebuild and verify an exact-source install after the code stack settles,
then record user acceptance against those real observations.
