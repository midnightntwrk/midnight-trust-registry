# 0.1.0 Acceptance Evidence Map

Status: local working index, not an issue-closure or release approval record.
The first 0.1.0 candidate is self-hosted local/offline runtime only. Preprod
is deferred to a later public-network release. Simulator and mocked-provider
tests below cannot close live local-ledger or egress-denied gates.
Kubernetes and Helm are optional deployment paths, not 0.1.0 RC gates.
The non-Kubernetes standalone installation may qualify with equivalent
deployed-ledger, offline actor, restart/restore, and security evidence.

## Current review and operator handoff (2026-10-28)

Published draft PRs [#238](https://github.com/midnightntwrk/midnight-trust-registry/pull/238)
(`97e59c5e`), [#239](https://github.com/midnightntwrk/midnight-trust-registry/pull/239)
(`fa7bf067`), and [#240](https://github.com/midnightntwrk/midnight-trust-registry/pull/240)
(`8dc05ec7`) remain stacked, draft, and unmerged. At #238's exact head, the
milestone build/package/test, quality, documentation, and aggregate scan checks
passed; #239 and #240 passed their exact-head stacked light and docs checks.
the separate external Opengrep OSS check remains red for five internal
plaintext WebSocket links. [#237](https://github.com/midnightntwrk/midnight-trust-registry/issues/237)
requires a reviewed security disposition; a green aggregate scan is not a
waiver. The later local review groups and recovery fixes are unpublished, so
their tests do not change those PR heads or CI results.

The clean unpublished development stack was merged locally onto #240 at
signed/DCO `0527e11af09327fef15427f148ba07c8688d0f01`, without rewriting
its original branch. At that source, focused acceptance and security-verdict
tests passed 22/22, standalone topology passed 120/120, the strict security
script typecheck passed, and `pnpm audit --audit-level low` found no known
vulnerabilities. At the subsequent signed/DCO documentation head
`f20cf27d337f0ce091b09a496901d8bccdeb6f9c`,
`pnpm run test:e2e:demo:browser` passed four simulator-backed role journeys,
fixture CLI/API and UI smoke, and 11 Playwright cases. This is the current
local fixture E2E checkpoint, not a deployed-ledger test. These checks do not
authenticate finality or establish deployed, egress-denied standalone actor
journeys, and they pass no `L01`-`S01` acceptance case.

At signed/DCO local source `3fddcac5623b58cfecdd672cefa557ef3b691b20`,
`pnpm run test:e2e:demo:browser` passed the four simulator-backed membership
journeys, fixture CLI/API and UI smoke, and 11 Playwright cases on
2026-10-28. `pnpm run test:standalone-topology` separately passed 117/117.
These are implementation and fixture/topology checks only. They did not
deploy or read back a finalized standalone contract, exercise a live
VC-owned status authority, deny egress for deployed actors, or restore a
deployed registry. They do not pass any `L01`-`S01` acceptance case. This
documentation update is newer than the tested source and must be retested
as part of an exact-source release candidate.

At signed/DCO local source `27f873601bc168859b470c858aa06fd23e47a7c3`,
`pnpm run test:e2e:demo:browser` exited 0 on 2026-10-28. The four signed
membership simulator journeys, fixture API/UI smoke, and all 10 Playwright
browser cases passed. The adversarial parity command at the same source
reported 198 demo IDs, 198 isolated IDs, and no missing cases; the full light
run passed 20/20 tasks. This is a development E2E checkpoint only: it used
fixture identity/status and a Compact simulator, not a deployed, finalized,
egress-denied standalone Trust Registry. No `L01`-`S01` case is promoted by
these results, and this documentation commit will itself have a later SHA.

The retained private `wizard-b23` packet is bound to signed source `6a5b2529`
and is older than the current local implementation. A read-only prerequisite
check against its own source returned exit 2: install staged, stack observed,
and setup unlocked were true; `genesisApproved` was the first missing gate.
Release roster approval, deployment, committee approval, verifier-key
reconciliation, and maintenance transition were also missing. This packet is
pre-deployment evidence, not an exact-current-source release candidate. Its
node-reported genesis proposal must not be promoted to a trusted pin by the
wizard or an AI agent.

The operator's next action is to freeze the intended exact source, rebuild
and verify its pinned install, independently authenticate the real chain
specification, then review and sign the exact genesis approval. Separately,
a human reviewer must approve the release committee threshold, public keys, and
custody roles before deployment. Only then can a deployment produce finalized
contract and key readback, followed by the maintenance transition, signed API
plan, egress-denied actor journeys, and deployed restart/restore. The VC-owned
live status adapter and independent human security verdict remain separate
release gates. Do not count current fixture, preflight, loopback HTTP, or
node-self-reported checks as those deployed results. Keep #198 draft.

## Latest local pre-deployment checkpoint

The most recent source-matched **pre-deployment** packet was prepared from
signed/DCO source `779bfd1d0b72fd02cb3320511212d9ebd73cc334`. Its verified
v6 install inventory SHA-256 is
`66f8d669eb2b06e90f3444c27a0c69f5368f007568f28b757e156229c7e6154d`
and covers ten packed packages, six pinned images, and 18 proof-parameter
files. Packed actor and VC consumer fixture checks passed. The dedicated
`wizard-779bfd1` bridge matched the bundle's three ledger images and passed
bridge-scoped HTTP/DNS egress-canary denial. A pre-deployment restart retained
the node-reported finalized checkpoint hash while its height advanced from
49 to 61. Its node-reported genesis candidate SHA-256 is
`86925630cc88da02765de3fe33e2185a81479ecb1087ed3c9668ec43cf5627b9`;
the proposed pin SHA-256 is
`d1a207e5a816314c2c485b18dd46d958b894be4b52e98ec2058c8f7b97cc8de1`.
Both remain **untrusted node-derived proposals**. The prerequisite checker
exited 2 at `genesisApproved`; the three dedicated containers were stopped,
with private evidence and volumes retained. The packet did not deploy a
contract, authenticate finality independently, run an offline actor, or test
deployed restore. This documentation update is newer than the recorded source,
so the `779bfd1d` bundle is not an exact-head release candidate. Do not sign
the proposed pin as a final release approval while the implementation stack
is still changing.

The operator's next safe action is to freeze and independently review the
intended release source and chain specification, then regenerate a
source-matched bundle and approval draft. The human reviewer, not an AI or
node report, signs the exact wizard approval bytes. Separately approve the
release committee threshold, public keys, and custody roles before attempting
deployment. Retain the failed prerequisite report as evidence of the stop.

### Historical checkpoint

The private `artifacts/standalone-setup/wizard-7efc-1/` setup was built from
signed/DCO source `7efcf60760dc7e37641f7c8f3b575dc83fd5dd6b` and a
verified v6 install inventory with SHA-256
`cf816e832bf0b554f886194bce9fa255ad602598dfc4cbea3b7afe3ac81036a8`.
The bundle check covered ten packages, six images, and 18 proof-parameter
files. Its dedicated node/indexer/prover bridge passed image and Compose
matching, local HTTP and DNS canary-denial checks, and pre-deployment restart
continuity (node-reported height 33 before, 43 after). The untrusted genesis
candidate and proposed pin have SHA-256 values
`11bf275076028efadc8884d67c4abf60b99e4d60c406d7e02c6405fd292731e8`
and `614d28894283b3262cc5135fb5e190f4107054c9125090911ef7b8f8f6345a75`.
The three containers are stopped; their volumes and private evidence remain.
The journey-prerequisite check exited 2 at the unsigned genesis gate. No
contract was deployed, no independent finality was authenticated, and no
offline actor or restore test ran. Current local source has advanced past
`7efcf607`, so this bundle is historical pre-deployment evidence, not an
exact-head release candidate. The earlier checkpoints below are retained
only as an audit trail.

At signed local source `ef6a9644`, the safe prebuilt regression lane found
all 66 full proof circuits and passed 349 integration, 109 API integration,
59 applicant, and 25 admin tests. The fixture demo passed four signed role
journeys plus CLI/API and both UI smoke surfaces; Playwright passed 10
fixture-browser cases. The standalone topology lane passed 89 isolated
orchestration tests. These checks did not authenticate the provenance of the
retained proof artifacts, deploy a contract, run a wallet or actor against
the ledger, or prove host-wide egress denial. They must not be entered as
`L01`-`S01` deployed acceptance results.

The open [0.1.0 issues](https://github.com/midnightntwrk/midnight-trust-registry/milestone/1)
must be reconciled against code and exact-head validation before closure.
The files below identify where to check behavior; their existence alone does
not prove every acceptance criterion. In particular, a simulator test is not
a finalized-network read, and a package smoke is not a live status proof.
The unpublished `codex/trust-registry-offline-egress-canary` slice at signed/DCO
`4719b01d` adds a v6-only local HTTP/DNS canary for the ledger bridge, replacing
the historical public-Internet positive control in the v6 wizard. Focused
orchestration tests, the standalone topology suite, documentation checks, and
dependency audit passed. A disposable Docker smoke with previously loaded
source-pinned node/API images returned HTTP 204 and resolved the canary on its
control bridge, while a separate internal bridge returned curl code 7 and DNS
code 2; all smoke resources were removed. This verifies the probe mechanics,
not an exact-source b23 or current-head ledger observation. Docker's default
address pools were exhausted on this host, so that smoke used two explicit
private /24 control subnets. The retained b23 install bundle predates a
currently required packed `reviewer-signature-status.js` file and fails the
current verifier; it must not be reclassified as current-source evidence.
No deployed contract, offline actor journey, or release gate was closed by
this probe.
The later private `artifacts/standalone-setup/wizard-31f6-1/` packet retains
a verified six-image v6 install at signed/DCO source
`31f6c5bbf9d0ddae6be090d7191748dd5cf642c2`, inventory SHA-256
`cec0e192f26d1e4c013cbf6729f3aeef6eb1aedf3b08ed61b5c5ae17d05fbce2`,
and an observed three-service internal bridge. The v6 local HTTP/DNS canary
passed against that live bridge without public Internet. Its node-reported
genesis candidate has SHA-256
`4fef60d63a3e3632c3c46c548b91d37d0d695b1413ff26629c5c5d78244c1a32`
and remains **untrusted**. Separate node, indexer, and proof-server restarts
preserved the finalized checkpoint hash and advanced the node-reported height
from 26 to 40. The private status still reports `localLedger: pending`,
`deployment: pending`, `restartRestore: pending`, and `releaseQualified: false`.
The newer signed `ed1260a3` source forwards an explicit control subnet through
the wizard, so even this successful pre-deployment packet is no longer an
exact-current-head release candidate. No signed genesis approval, deployed
contract, authenticated finalized readback, actor journey, or restore test
occurred. A later development probe against the retained `31f6` bridge used
the verified image IDs with a synthetic DNS/UDP canary. A positive control
answered before and after the isolated attempt, while the canary query count
did not advance during that attempt; local TCP and DNS/UDP canary routes were
denied. This was run with newer source than the install bundle and was not a
wizard release observation. It does not establish general DNS isolation or
egress denial for deployed services or actors. Both projects' volumes and
private evidence remain retained.

The earlier retained pre-deployment bridge observation **b33** was bound
to signed/DCO source `8957d96d29554e7ed9be9cd692b2a00d7c819e3f` and
verified v6 install inventory SHA-256
`7736b31041275795895641b0383c24a21f48c22cf195b35b330c6ef8bb15556e`.
Its isolated node, indexer, and prover matched pinned image IDs and Compose
bytes; a canary HTTPS/DNS probe was denied on the internal bridge. The
untrusted node-reported genesis candidate and proposed pin have SHA-256 values
`4a1e72d261cc59baf22271a556e856ef4dd214cef912a5c7c888dd2d929530ea`
and `d26d44bff594d974a43b7cca763fc3c0025167725d0314c3314b99a8ac48209e`.
The private `artifacts/standalone-setup/wizard-b33/` directory retains the
review packet and operator handoff; its relay was removed and its containers
were stopped with volumes preserved. No signed genesis approval, deployed
contract, finalized contract readback, approved maintenance transition, or
offline actor journey has occurred. Later local commits changed the source,
so b33 is **historical pre-deployment evidence**, not an exact-head candidate
to approve or deploy. A new source-matched install and packet are required
after code stabilizes. Earlier b28 and node-1.0.400 compatibility observations
remain historical; neither independently approved a genesis hash.

The later private `artifacts/standalone-setup/wizard-cf5d-1/` packet is bound
to signed/DCO source `cf5d8d3d68e1438f5044c0fac161765cdd32441d` and
verified v6 install inventory SHA-256
`3d46b6a1f4541a558a7ffc6ad5b5a8764e458b846d6895c81ec58f8efa6e022e`.
The isolated three-service bridge passed image/Compose matching and local
HTTP/DNS canary-denial checks. Its node-reported candidate and proposed pin
have SHA-256 values
`11f1fdb6498b0552818b124c1438b552954434e1a9b2916c8b7345f170075de4`
and `c881c473e76d4660a58fa312f9931d0449dd94c1dc577e01225dad0fa9c34b43`;
both are **untrusted**. The private review packet explains the independent
chain-spec comparison and exact-byte human signature required next. Restart
smoke preserved the node-reported finalized checkpoint at height 21 while
height advanced to 31. This is pre-deployment continuity only: contract
readback was not verified, cross-host restore was not run, and no actor
transaction occurred. The temporary install relay was removed and the three
dedicated containers were stopped; named volumes and private evidence remain.
The newer signed/DCO `d4b3b345` source strictly checks the packet I/O boundary
but does not match that retained install. The packet remains historical input
for review, not an exact-current-head release candidate. A candidate using
the newer source requires a fresh source-matched install and approval packet.

The historical checkpoints in the table and paragraphs below remain as an
audit trail, not as current-head release evidence.
An earlier retained verified-staged install is b22, pinned to signed source
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
| Standalone offline runtime | The [qualification plan](../guide/standalone-offline-runtime.md) separates online installation from offline runtime. The `7efcf607` source-matched v6 install and `wizard-7efc-1` bridge in the checkpoint above passed pinned-byte, topology, local canary-denial, and pre-deployment restart checks. Its genesis candidate, proposed pin, and review packet remain private and unsigned. Newer source makes this historical, not current-head release evidence. A fixture journey and a healthy local bridge do not prove a deployed registry. | Build a new exact-source install and genesis packet after the current code stabilizes. The human reviewer must independently check its chain-spec/genesis, source, inventory, and proposed pin, then inspect and detached-sign the wizard-generated approval bytes; neither chat approval nor the node candidate suffices. Live local deployment and authenticated finalized contract readback, approved release maintenance transition, wallet/API/browser egress-denied actor journeys, post-deployment restart and distinct-project restore with contract/wallet/API readback, and independent security review remain open. Pre-deployment smoke closes none of those gates. |
| #219 ledger-backed API | Local signed slices require a detached reviewer-signed, time-bounded v3 plan and approval-chain handoff, exact install/release bytes, pinned genesis/address/endpoints, per-query finalized readback, and complete current-map Compact projection checks. Historical authorization, recognition, and TRQP decision/evidence routes deliberately return `501 historical-decisions-out-of-scope`. The packaged signed-plan CLI remains read-only; `GET /health` lists no governed proposal ports. An opt-in issuer proposal port has signed writer-annex, provider-identity, journal, and injected-finality/evidence checks in tests, but no production embedding host or live VC-owned status adapter is installed. No API has run against a deployed local contract. | **Current-only 0.1.0 scope is decided.** Keep historical completeness deferred. Supply approved live DID/VC/status and authenticated-finality dependencies, wire the governed ports and durable admission to the exact signed plan, and run issuer through recognition actor writes on one deployed local ledger. After every mutation, drain queries and manually review, re-sign, install, and restart a versioned snapshot/plan set. The old plan must fail closed on changed sequence or deployment-image pins. Simulator and injected-provider tests cannot close this gate; offline actor, recovery, and security review are still required. |
| #218 Helm deployment (optional, not an RC gate) | The issue defines pinned images, isolated local node/indexer/prover, API and portal workloads, secrets, persistence, default-deny egress, first-run approval integration, and real-cluster qualification. The verified `7821a36` v6 install binds the API, admin, and applicant OCI archives to signed source and exact inventory bytes; the b14 Compose bridge runs only node/indexer/prover, not the API or portals. The local Helm chart has six private digest-pinned workloads, external Secret/PVC references, a namespace-wide default-deny policy, and narrow local operator/actor egress. The signed-render observer rejects an incomplete or narrowed policy set in tests. No Helm workload has been deployed or observed on a real cluster. | Track chart-specific cluster qualification separately from #45. Before claiming #218 complete, independently review final image/install bytes, bind running API and portals to approved image provenance, and install only in a dedicated namespace with trusted role-label admission. Plan/Secret/image and policy-object observations are point-in-time, not measured CNI egress enforcement or live cluster evidence. Qualify chart Secret/PVC ownership, DNS recursion and CNI behavior, local DID/VC/status authority allowlists, first-run wizard handoff, private preload, real isolated-cluster deployment, egress-denied actor journeys, restart/restore, operator compatibility matrix, and independent security review. Template tests are not cluster evidence. None of this makes Kubernetes a prerequisite for the standalone RC. |
| #230 proposal quarantine across restart | At signed local `e4c96ae9`, `node --test scripts/proposal-journal-process-restart.test.mjs` passed both fresh-process reservation/retry and forced-kill cases; the API package's `proposal-journal-process-restart.test.ts` passed three fresh-provider/journal cases. They assert no second submission callback after ambiguity, no callback after reservation write failure, a lagging read stays blocked, and a matching finalized observation permits a different intent but not replay. | These are injected-provider and journal mechanics tests, not a restarted deployed provider or independently authenticated finality. Keep the real local-ledger restart/restore and ambiguous-outcome evidence under `R01` open; do not clear a never-observed reservation from a null read or timeout. |
| #236 manifest-backed publication | At signed local `e4c96ae9`, `pnpm run test:artifact-workspaces` passed 67 tests. The publish workflow generates and verifies a source-bound manifest over `artifacts/npm-release`, runs manifest-backed clean-consumer smoke, and rechecks each selected tarball before publish; negative tests reject altered artifacts, incomplete proof parameters, missing manifests, and mismatched registry integrity during resumed publication. | Re-run the full Compact build, manifest generation, tampered-artifact negative, and clean-consumer smoke on the exact final candidate in protected CI. The release owner must approve the reviewed manifest and distribution channel; local workflow tests do not authenticate the runner or authorize publication. |
| #45 release | Signed-source manifest generator, package hash verifier, ten packed artifacts, four HTTP membership journeys plus one packaged recognition VC/VP journey, and draft [candidate note](../guide/release-candidate-0.1.0.md). The cf5d verified install binds source-matched packages, six images, and proof parameters; it is not installed-runtime or current-head deployment evidence. At signed local `d4b3b345`, `integration:prebuilt` found all 66 full proof circuits and passed 349 integration, 109 API integration, 59 applicant, and 25 admin tests. The simulator/fixture `test:e2e:demo` and all 10 fixture-browser tests also passed. None of these tests is a deployed local-ledger actor journey or final-candidate validation. | Full integration from final source, packed-consumer checks, and artifact review at the final candidate revision, exact-head CI/review, release owner, independent local security review, deployed local-ledger qualification, and recovery approval are pending. |
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
The unpublished admin-console stack through signed/DCO `238b4bd` checks local API
health before showing a current-only exact-ID lookup, hides fixture mutation
controls and workspace signing in local-ledger mode, and rejects a changed
checkpoint, mismatched record, or stale in-flight lookup. Its 24 focused UI
tests use mocked HTTP and do not prove a deployed ledger or offline browser
journey. Kubernetes and Helm remain optional; no cluster evidence is required
to qualify the non-Kubernetes 0.1.0 RC.
The adjacent unpublished applicant-portal slice checks local health before
inspection, never calls list routes in current-only mode, and requires an
unchanged reported plan, registry, and finalized checkpoint around exact
authorization and recognition reads. Its portal tests also use mocked HTTP;
they cannot close the deployed-ledger, finality, or offline actor gates.

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
The local draft/verify commands bind the exact review candidate, distinct
reviewer key, draft time, and retained finality-evidence bytes. Verification
alone marks finality unverified, release unqualified, and retry forbidden.
The opt-in `FileProposalSubmissionJournal.abandonInvalidatedReservation`
method now re-assesses the candidate under its journal lock, requires a
deployment-owned finality authenticator and the exact detached-signed
decision, and durably retains a terminal, non-replayable tombstone. Local
tests cover competing journal instances, late receipts, rotation, restart,
and a new proposal without replay of the original ID. The authenticator in
those tests supplies an injected simulator view, not independent local-ledger
finality. No reviewed production authenticator, complete-action proof format,
deployed stale-action check, or operator CLI/HTTP path exists. #220 remains
open; neither a signed decision nor the local unit tests authorize release
of a real reservation, and the `R01` recovery gate is still unproven.

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
