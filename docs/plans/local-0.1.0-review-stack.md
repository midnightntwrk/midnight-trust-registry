# Local 0.1.0 review stack

This is a **local, unpublished** review plan, not a set of open pull requests.
The first release candidate is self-hosted/local-only. Public Preview,
Preprod, and Mainnet qualification is deferred. Helm is optional and must not
block the local RC. Keep #198 draft until its scope and release gates are
explicitly updated. Do not publish or merge any branch solely because it
appears in this list.

Open the following branches bottom-up. Each PR targets the preceding row's
branch; row 1 targets `milestone-0.1.0`. The existing linear history is
retained, so no signed commits need rewriting. The abbreviated SHAs are
verification hints; resolve exact remote heads before publication.

| Order | Head branch | Local head | Review focus |
| --- | --- | --- | --- |
| 1 | `codex/trust-registry-canonical-bundles` | `f31245f` | Release manifest, adversarial isolation, nonce capacity, deployment image readback, canonical governance bundles |
| 2 | `codex/trust-registry-rc-foundation` | `fc5fc34` | DID/VP signature boundaries, governed verifier lifecycle, schema-grant checks, initial local RC scope |
| 3 | `codex/trust-registry-standalone-setup-wizard` | `0d6e791` | Local deployment/finality path, pinned offline install, isolated ledger stack, resumable first-run wizard |
| 4 | `codex/trust-registry-staged-verifier-install` | `9a315f2` | Development wallet, reviewer-signed genesis, committee roster, staged verifier-key installation |
| 5 | `codex/trust-registry-deployment-bound-committee` | `d05b963` | Journaled key insertion and maintenance transition, egress smoke, recovery and deployment binding |
| 6 | `codex/trust-registry-rc-standalone-installer` | `49df9f9` | Verified stack topology, first-run approval drafts, genesis-review handoff and restart observation |
| 7 | `codex/trust-registry-install-api-image` | `1880aa9` | Signed read-only local API mode and pinned, reproducible API OCI image |
| 8 | `codex/trust-registry-egress-network-continuity` | `e1f4a28` | Optional Helm chart/observer, portal images, bounded local network and egress probes |
| 9 | `codex/trust-registry-reviewer-public-key-export` | `319cf87` | Static portal readback, installation relay, predeployment restart/restore evidence, isolated reviewer keyring |
| 10 | `codex/trust-registry-wizard-reviewer-signature-verified` | `6d8c98c` | Signed approval validation, release-manifest binding, local API history limits and Helm observation hardening |
| 11 | `codex/trust-registry-helm-api-plan-binding` | `33c9395` | Packed release identity, current-only API plan, preflight and runtime binding; Helm remains optional |
| 12 | `codex/trust-registry-rc-local-gates` | `0bd95cf` | Local qualification hardening, restore evidence, egress route checks, current finalized API scope |
| 13 | `codex/trust-registry-rc-current-plan-expiry-verified` | `5079a57` | Journaled local issuer proposals, pinned submission, ambiguous-outcome quarantine and recovery inspection |
| 14 | `codex/trust-registry-restart-private-inputs` | `a4cd94a` | API runtime/egress observations, signed-plan expiry, adversarial reports, portal current-state reads, private restart inputs |
| 15 | `codex/trust-registry-local-applicant-current` | `6a5b252` | Source-checkpoint readback, signed recovery decisions, current-only admin and applicant behavior |
| 16 | `codex/trust-registry-network-profiles` | `ca9a184` | Validated standalone/Preview/Preprod/Mainnet profiles without universal genesis hashes |
| 17 | `codex/trust-registry-package-export-policy` | Resolve locally | Align release package policy with the pinned submission-provider export and its packed import smoke |

## Publication gates

- Obtain explicit approval before any push or PR creation. Recheck that each
  branch head is still the intended descendant of its proposed base.
- Run required validation and independent exact-head review for each PR;
  local tests at the top of the stack do not substitute for each PR's CI.
- Preserve the verified install bundles, generated Compact keys, private
  setup evidence and active ledger volumes. Do not run destructive light/full
  build targets in the artifact-bearing checkout.
- Keep #198 draft. No row proves release readiness or authorizes a public
  deployment. The current exact-source install bundle predates row 16.

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
