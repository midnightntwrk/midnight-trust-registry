# 0.1.0 Acceptance Evidence Map

Status: local working index, not an issue-closure or release approval record.
The first 0.1.0 candidate is self-hosted local/offline runtime only. Preprod
is deferred to a later public-network release. Simulator and mocked-provider
tests below cannot close live local-ledger or egress-denied gates.
Kubernetes and Helm are optional deployment paths, not 0.1.0 RC gates.
The non-Kubernetes standalone installation may qualify with equivalent
deployed-ledger, offline actor, restart/restore, and security evidence.

The open [0.1.0 issues](https://github.com/midnightntwrk/midnight-trust-registry/milestone/1)
must be reconciled against code and exact-head validation before closure.
The files below identify where to check behavior; their existence alone does
not prove every acceptance criterion. In particular, a simulator test is not
a finalized-network read, and a package smoke is not a live status proof.
The latest retained verified-staged install is b22, pinned to signed source
`9c7d4f5fcddb80464787ba30af2d4d8e6db897c6`. Its inventory and release
manifest SHA-256 values are `66e288fc7ecfd04c2ac11b4f644f3f77a308fb5850a08ecd7ca7b20b1b9d0ed0`
and `ea7b0c01d7e430dfd436bbe522daed074c0f3ffa6f3f0ba5048b48b9afdaa08e`.
The b22 node/indexer/proof bridge is observed, but its candidate genesis and
proposed pin remain untrusted. No human-signed approval, contract deployment,
finalized contract readback, or offline actor journey exists at b22. The
private review packet is `artifacts/standalone-setup/wizard-b22/genesis-review-packet.md`.
Do not sign an older setup packet for this source. Any later runtime-source
change requires a new exact-source install and review. Retain earlier volumes,
private evidence, and generated proof artifacts until safe phase-exit cleanup.

| Issues | Current executable evidence | Still required before closure |
| --- | --- | --- |
| #39 historical API/TRQP | Fixture/simulator tests exercise timestamped native evaluation and historical TRQP evidence. The local-ledger API deliberately returns `501 historical-decisions-out-of-scope` for historical authorization, recognition, and TRQP decision/evidence routes. | Historical decisions are deferred beyond the local-only 0.1.0 RC. Keep #39 open or explicitly re-scope it; do not count fixture history as deployed local history. |
| #58, #59, #78 actor journeys | `scripts/demo-governed-registry.mjs`; `scripts/demo-signed-membership-journey.mjs` for issuer, verifier, auditor, maintainer; `scripts/packed-recognition-journey.mjs` emits a scrubbed accreditation, signer, policy, epoch, and rejection report, checks the retained proposal signature, and queries recognition evidence through the packaged public API (200/403/404/503). At source `a94520e`, manifest-backed `packed-artifacts:smoke -- --actor-journey --vc-consumer` installed all ten verified bundle tarballs in a temporary consumer and passed the actor journeys and VC Ledger 8 fixture check; the temporary consumer was removed. | Pass full integration at the final candidate SHA and confirm all issue-specific negatives. The packed journeys use a simulator and loopback HTTP, not a deployed local-ledger runtime or offline actor evidence. |
| #60 adversarial matrix | The governed demo emits invariant, boundary, expected, and observed categories; Compact/API/client/TRQP tests cover additional failures. The isolated runner checks exactly 198 individually attributed cases. Its clean-head archive at signed `bbb2c456a93aa035ac482d67f945e8cddf6dfb7c` recorded 198/198 passes and 198 demo case IDs, with private report SHA-256 `4dc5ccfecd389c26c234673fd5178e2f3ada32efea14718bd2ae090870c8280b`. | Audit every issue case against its actual boundary and retain an archive from the final candidate. Expired evidence is currently checked before Compact, which has no trusted time input; do not claim an on-chain expiry rejection. Historical API routes are deferred in the current-only RC and the older issue wording still needs reconciliation. The archive is neither deployed-ledger actor evidence nor final-candidate validation. |
| #67, #75, #76 evidence and policy | `contracts/trust-registry/src/test/trust-registry.test.ts`; `packages/trust-registry-integration/src/test/application-status-attestation.integration.test.ts`; `packages/trust-registry-integration/src/test/application-evidence-decision-preflight.integration.test.ts` rejects stale accepted evidence before signing after policy revision, governed verifier-key rotation, suspension, or revocation, while fresh evidence uses the replacement key across all four applicant roles; `packages/trust-registry-integration/src/test/evidence-verifier-did-key.integration.test.ts` checks the active Compact key record against a resolved DID assertion method before and after rotation; `packages/trust-registry-api/src/integration-test/governed-policy-http.integration.test.ts` exercises externally signed verifier-key lifecycle requests through Compact; `packages/trust-registry-api/src/integration-test/did-bound-evidence-verifier-policy-port.integration.test.ts` checks DID binding and exact action payload at prepare and execution; `packages/trust-registry-api/src/test/signed-mutation-http.test.ts`; `packages/trust-registry-api/src/integration-test/compact-proposal-observation.integration.test.ts` reconstructs and checks all five proposal signatures, rejects substituted ledger joins, and preserves historical verification for all five roles after verifier-key retirement | Match role-specific VC/VP, policy-rotation, evidence-verifier, and privacy criteria to exact tests; pass full integration. The DID-bound lifecycle wrapper still requires independently finalized DID and registry readers and atomic check/execution integration; its Compact-backed test uses a simulator, not production public-network authority or finality proof. The proposal projection trusts the supplied finalized ledger and does not supply an independent inclusion/finality proof. |
| #77 signed mutation | `packages/trust-registry-api/src/test/signed-mutation-http.test.ts`; `packages/trust-registry-api/src/test/mutation-intent-preflight.test.ts`; four packed actor journeys | Confirm restart, conflict, and all unauthenticated-write denials at the candidate revision. |
| #79, #73 VC anchor and Ledger 8 consumer | [Vector audit](vc-signer-authorization-vector-audit.md) maps source and packed-consumer cases; `packages/trust-registry-integration/src/test/decision-evidence-simulator.integration.test.ts` signs from an exact schema grant and rejects its suspension; `packages/trust-registry-integration/src/test/vc-scope.test.ts` rejects other issuer grant types as schema signer authority; `pnpm run packed-artifacts:smoke -- --vc-consumer` compiles the exported fixture from a tarball-only install | Run full integration and compare exported vectors with VC conformance at the candidate SHA. Distinguish local compiled consumption from deployed synchronous cross-contract calls; host-authenticated finalized registry/DID readers remain deployment dependencies. |
| #201, #202 signer and nonce rules | `contracts/trust-registry/src/test/trust-registry.test.ts` rejects unsorted, duplicate, nonzero-padded, and zero signer slots; `packages/trust-registry-integration/src/test/external-epoch-publication.integration.test.ts` sorts a reversed signature input and checks the resulting signer-set and event hashes; [ADR-0001](../decisions/adr-0001-governance-evidence-and-policy-snapshots.md) records the Compact size tradeoff. `packages/trust-registry-api/src/test/signed-mutation-state.test.ts` checks expiry pruning, actor and global live-window capacity, clock rollback, and keyed lookup; `packages/trust-registry-api/src/test/signed-mutation-http.test.ts` checks cross-actor saturation, concurrent reuse, and replay after server restart; `packages/trust-registry-cli/src/test/trust-registry-cli.test.ts` validates and explicitly rejects old workspace formats. The 10,000-entry/5,000-lookup local benchmark (`node scripts/bench-mutation-nonce-lookups.mjs`) measured 0.2 ms keyed versus 745 ms linear on Node 24/Darwin ARM64; this is a local microbenchmark, not a CI latency guarantee | Pass exact-head full integration and link the signed implementation commits after merge. Confirm pre-release snapshot migration or rejection in the final package review. |
| #90 issuer status policy | The issuer status binding and application status-attestation tests verify a governed commitment and reject substitution | A consumable VC-owned status-authority adapter is still missing. The current VC status-registry package is private and reference-tier; its own `docs/spec/status-time-authority-v1.md` leaves B1 authenticated authority, B2 accepted root/non-membership, and B3 trusted time as implementation gates. Select an approved verification profile and satisfy its gates before wiring a supported non-revocation result or restoring a federation status claim. Fixture evidence is not live status authority. |
| #200, #213 public deployment, deferred from local 0.1.0 RC | Constructor, deployment-domain, replay, provider-adapter, one-attempt deployment and committee-submission journals, Ledger 8 committee-update preparation, and read-only finalized-state reconciliation tests exist; network and genesis are configurable. The [Preprod admin runbook](../guide/preprod-admin-qualification.md) is for a later public-network release | A funded operator, approved genesis and committee pins, real Preprod deployment with independently finalized readback, custody and recovery review, and actual committee transition remain required for that later release. This deferral does not waive the analogous local-ledger and maintenance gates below. |
| Standalone offline runtime | The [qualification plan](../guide/standalone-offline-runtime.md) separates online installation from offline runtime. Signed source `f48fbb9b004e1fcfa2de61c27756324584f080a3` has a separately checked v6 install inventory SHA-256 `d72798c39a414bd3caf2ab2c11cb3f2926909823f2f9054344f48e2bcbef8c14`, with ten packages, six OCI archives, and 18 proof-parameter files. The b19 node/indexer/prover bridge matched the pinned images and Compose bytes; its canary HTTPS/DNS egress probe was limited to that bridge. Its node-reported candidate SHA-256 `3dac702d930c525a1b384d095fa548e94ae3e5adef4523bcf789ba853c9d0a8a`, proposed pin SHA-256 `fd2a3ccbad37084373b157986b441334a9bb1ddad109cc0540f9e79c165a1544`, and unsigned private `artifacts/standalone-setup/wizard-b19/genesis-review-packet.md` are not approved genesis evidence. The temporary installation relay was removed. The b19 containers are stopped with volumes and evidence intact. Earlier b17 pre-deployment restart retained the finalized height-69 hash and advanced to height 77, but does not qualify b19 or a deployed contract. | Build a new exact-source install and genesis packet after the current code stabilizes. The human reviewer must independently check its chain-spec/genesis, source, inventory, and proposed pin, then inspect and detached-sign the wizard-generated approval bytes; neither chat approval nor the node candidate suffices. Live local deployment and finalized contract readback, approved release maintenance transition, wallet/API/browser egress-denied actor journeys, post-deployment restart and distinct-project restore with contract/wallet/API readback, and independent security review remain open. Pre-deployment smoke closes none of those gates. |
| #219 ledger-backed API | Local signed slices require a detached reviewer-signed, time-bounded plan, exact install/release bytes, pinned genesis/address/endpoints, per-query finalized readback, canonical JSON, and complete current-map Compact projection checks. Historical authorization, recognition, TRQP decision/evidence, and epoch-resolution/by-id routes explicitly return `501 historical-decisions-out-of-scope`; fixture history is not local-RC evidence. The v2 API plan commits to the complete release-manifest verifier-key catalog and an expected maintenance authority, comparing both to the same finalized contract-state read in local tests; no reviewer-signed b19 plan exists yet. A no-listener `check-local-ledger-plan` preflight uses the signed plan and pinned install/source/snapshot bytes. The verified-staged b19 v6 install includes source-matched API and portal images plus a pinned optional API Compose overlay; the tested CLI profile is read-only on the internal ledger network. No API has run against a deployed local contract. | **Current-only 0.1.0 scope is decided.** Keep historical completeness and versioned on-ledger transition commitments deferred; the Compact current map and unordered event hashes cannot prove complete ordered history. After every governed mutation or maintenance-image change, drain queries and manually review, re-sign, install, and restart a versioned snapshot/plan set. The old plan must fail closed when its sequence map or deployment-image pins no longer cover the finalized state; no fixture fallback or stale-plan rollback is allowed. Test this rotation with real finalized local actor journeys. The signed map remains a reviewer attestation, not independent proof of indexer finality; authenticate the checkpoint, bind the running API image to approved install bytes, authenticate DID/VC/status and off-chain metadata, then complete deployed offline journeys and recovery/security review. |
| #218 Helm deployment (optional, not an RC gate) | The issue defines pinned images, isolated local node/indexer/prover, API and portal workloads, secrets, persistence, default-deny egress, first-run approval integration, and real-cluster qualification. The verified `7821a36` v6 install binds the API, admin, and applicant OCI archives to signed source and exact inventory bytes; the b14 Compose bridge runs only node/indexer/prover, not the API or portals. The local Helm chart has six private digest-pinned workloads, external Secret/PVC references, a namespace-wide default-deny policy, and narrow local operator/actor egress. The signed-render observer rejects an incomplete or narrowed policy set in tests. No Helm workload has been deployed or observed on a real cluster. | Track chart-specific cluster qualification separately from #45. Before claiming #218 complete, independently review final image/install bytes, bind running API and portals to approved image provenance, and install only in a dedicated namespace with trusted role-label admission. Plan/Secret/image and policy-object observations are point-in-time, not measured CNI egress enforcement or live cluster evidence. Qualify chart Secret/PVC ownership, DNS recursion and CNI behavior, local DID/VC/status authority allowlists, first-run wizard handoff, private preload, real isolated-cluster deployment, egress-denied actor journeys, restart/restore, operator compatibility matrix, and independent security review. Template tests are not cluster evidence. None of this makes Kubernetes a prerequisite for the standalone RC. |
| #45 release | Signed-source manifest generator, package hash verifier, ten packed artifacts, four HTTP membership journeys plus one packaged recognition VC/VP journey, and draft [candidate note](../guide/release-candidate-0.1.0.md). The verified-staged b19 `f48fbb9` install inventory binds source-matched packages, six images, and proof parameters; it is not installed runtime evidence or current-head validation. Full integration and all 66 verifier-key hashes passed at `f48fbb9`, before the later crash-recovery fix. Manifest-backed packed-consumer actor and VC Ledger 8 fixture smokes passed at earlier source `a94520e`, but neither is a deployed local-ledger actor journey or final-candidate validation. | Full integration, packed-consumer checks, and artifact review at the final candidate revision, exact-head CI/review, release owner, independent local security review, deployed local-ledger qualification, and recovery approval are pending. |
| #178 milestone protection policy | The [delivery harness](milestone-0.1.0-delivery-harness.md) requires green exact-head CI and current-head LLM review; the user explicitly declined a milestone branch-protection rule | Reconcile the stale issue with that policy decision; do not treat absence of branch protection as a release blocker or relax develop/main protections. |

An earlier retained exact-source install was **b20 at signed/DCO
`5e01191e7d4289911c0e2fb53c639d258dc86832`**, superseding the b19
evidence in the table above. Its verified v6 inventory SHA-256 is
`8c863ed505a1470509bdb79ce047ee795c9e2331901708ddf16baee0819e43ac`;
the release-manifest SHA-256 is
`386a21ddd985339146b0fb35bab8065f3c66cb329bf588a7577ade6b5f3297ef`.
Full `./run.sh integration` passed at that source and all 66 source-managed
and 66 dist verifier files matched the manifest. A clean packed consumer
passed the Ledger 8 VC fixture and issuer, verifier, auditor, maintainer, and
recognition journeys; package-content checks passed for all ten packages.
The isolated b20 node/indexer/proof bridge and its HTTPS/DNS egress probe
covered those services only. Its unsigned private genesis review packet is
`artifacts/standalone-setup/wizard-b20/genesis-review-packet.md`; node-reported
candidate and proposed pin remain untrusted. No b20 contract deployment or
offline actor journey has occurred. The current local source is newer than
this bundle, so b20 cannot serve as final-head release evidence. The b22
checkpoint above supersedes b20 for latest runtime-source staging, not for deployment
qualification.

Local #219 API slices now return `503 local-list-projection-unavailable` for
authorization and recognition lists, and select current by-ID records from
the finalized current-scope indexes; superseded IDs return 404. The route
observation probe checks those fail-closed responses. Full API tests passed
at the unpublished current-only head, but these are injected-source tests,
not independent node/indexer inclusion proof or deployed offline API evidence.

The private proposal journal now blocks new governed proposals while any
ambiguous reservation remains, including across restart. Mocked/API tests
cover replay denial and a matching finalized observation, but a never-observed
attempt can still stop all new proposals. [#220](https://github.com/midnightntwrk/midnight-trust-registry/issues/220)
is a local RC blocker for an audited operator recovery path. A null indexer
read, elapsed time, or journal replacement must not bypass this gate. The
real-file-journal issuer HTTP regression also verifies that a deterministically
insufficient action quorum is rejected before reservation, with no Compact
execution; the focused four-test integration file passed at the unpublished
current head. This covers that pre-broadcast case only, not ambiguous recovery.
The Compact simulator regression shows that advancing the governance sequence
invalidates the old proposal signature without creating its record, but a
fresh signature for that ID still succeeds. This is not finalized local-ledger
evidence and does not replace the required durable tombstone. The
read-only v2 candidate report binds the exact approved API plan digest but
does not authenticate non-inclusion or authorize journal release. The current
indexer SDK returns contract state at a node-reported finalized block without
a machine-verifiable state proof; a reviewed evidence policy is still needed.
A bound journal with a missing state file now rejects writes instead of
starting empty, and a running instance detects loss of its checked binding.
Loss of both files across process restart still requires independent durable
recovery evidence and cannot be treated as a fresh installation.
The local signed recovery-decision parser now binds the exact review candidate,
reviewer key, decision time, and retained finality-evidence bytes. Its result
explicitly marks finality unverified, release unqualified, and retry forbidden.
It neither authenticates chain finality nor changes journal state. A future
release path must independently authenticate finality and re-assess the exact
candidate under the journal lock before any state change. #220 remains open:
an independently reviewed finality policy, durable tombstone, operator command,
restart/replay tests, and security review are still required before any
reservation can be released.

## Next Local Qualification Sequence

1. Keep using focused and light checks while the candidate tree changes. Full
   integration passed at signed `fc5fc3480705a9b438f5ca05bd327f8a09f75504`
   with 66 proof circuits, before the subsequent delivery-script and runbook
   edits. Turbo emitted a cache-write disk-space warning and duplicated the
   Compact build; do not treat this as exact-head evidence for a later commit.
2. At a stable clean signed/DCO candidate head, run full integration once,
   preserving its generated proof artifacts. Then run the full package-content
   check, repack, generate the manifest, and run the manifest-backed actor
   smoke. Record the exact source SHA and validation timings.
3. Audit each open issue's remaining checkboxes against the exact test result.
   Close only after a merged PR is linked with its merge SHA, validation
   commands, and deliberately deferred criteria. Leave #90, #200, and #45
   open while their real release dependencies remain.
