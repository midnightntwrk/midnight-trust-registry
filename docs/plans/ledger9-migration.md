# Ledger 9 migration plan

Status: local migration in progress. This document is not a deployed or release
qualification claim. The historical Ledger 8 source is the `ledger8` branch at
`5abc1575922d3f0cc7234f5f1d4c0a77e045fcfd`.

## Selected official matrix

| Component | Selected version | Current migration state |
| --- | --- | --- |
| Node | 2.1.101 | Live loopback check passes with `system_version` `2.1.101-86774edf` and runtime `specVersion` `2001100` |
| Ledger | 9.1.0.1 | Official image cohort and protocol-version evidence; no independent crate-version attestation from RPC |
| Indexer standalone | 4.4.101 | Live indexed block and matching genesis check passes |
| Proof server | 9.0.0 | Live loopback reachability check passes with read-only parameter cache and fetching disabled; no deployed TR proof run |
| Compact compiler | 0.36.0 | Full source-matched compile generates all 66 circuits and prover/verifier keys |
| Compact runtime | 0.21.0 | Locally installed with exact DID RC1 and VC PR #755 artifacts; simulator/integration tests pass, deployed runtime unqualified |
| Midnight.js / testkit-js | 5.0.0 | Locally installed; simulator/integration tests pass, deployed provider journey unqualified |
| Compact.js | 3.0.0 | Locally installed; simulator, client, harness, and integration tests use awaited circuit/read APIs |
| `@midnightntwrk/ledger-v9` | 1.0.0 | Required for new Ledger 9 transactions |
| `@midnightntwrk/onchain-runtime-v4` | 4.0.0 | Required where directly consumed |
| Midnight DID | exact 1.0.0-rc1 cohort | Published and installed locally under four dated, exact-version age exceptions |
| VC Compact and DID binding | PR #755 source, 0.4.0 artifacts | Built from exact PR head locally; not merged or published to npm |

## Localnet ownership and attach

For compatible development, attach read-only to the designated owner's shared
`midnight-network` stack instead of starting another stack. Run
`pnpm localnet:discover` from this repository (or
`pnpm check:ledger9-local-stack` to run its unit tests first). Both commands
only query loopback HTTP endpoints and never invoke Docker, start containers,
or change the shared project. If discovery fails, diagnose the reported
service and ask the designated owner; do not retry by starting a stack.
The failure output includes the diagnostic and this owner handoff. Only tests
requiring a fresh chain or incompatible versions should create a separate
`midnight-<repo>-<ledger>-<run-id>` project with Compose-managed volumes and
Docker-assigned loopback ports. That is a deliberate isolated run, not an
automatic fallback from shared-stack discovery.
The discovery command prints the verified node and indexer state plus client
URLs. Its defaults are node
`127.0.0.1:9944`, indexer `127.0.0.1:8088/api/v4/graphql`, and proof server
`127.0.0.1:6300`. The check requires node `2.1.101`, Ledger 9 protocol
`2001100`, matching node/indexer genesis and latest indexed block hash, and
proof-server `9.0.2`. The WebSocket URL in its output is derived from the
verified API v4 HTTP endpoint but is not itself handshake-tested. A passing
attach is infrastructure evidence only, not a registry deployment or
proof-submission test.

Run any shared-stack development workload through
`pnpm localnet:run -- <command> [args...]`. This wrapper performs the same
read-only discovery before spawning the command; on failure it reports the
diagnostic and does not spawn anything. Its own code never starts
`midnight-network`; do not pass a lifecycle command as the workload. The
wrapper honors the same `TR_NODE_PORT`, `TR_INDEXER_PORT`, `TR_PROOF_PORT`,
genesis, proof-version, and optional checkpoint overrides as discovery. For
this checkout, source the ignored, private `artifacts/ledger9-current-chain.env`
before discovery or `localnet:run` (for example,
`source artifacts/ledger9-current-chain.env` in a shell from the repo root).
It pins the owner's default ports, the
node-observed genesis, and an observed non-genesis block height/hash. A shared
stack replacement must fail this check even if the new chain uses the same
genesis. Re-observe and explicitly update the private pin only after confirming
the replacement with the stack owner; do not carry over deployment journals.
This local development pin is not a signed release approval or standalone
deployment plan.

`pnpm localnet:discover` and `pnpm check:ledger9-local-stack` are the current
shared-stack root targets. Fixture demos and simulator integration do not use
a live stack and must not acquire one. The standalone wizard and direct
deployment/key-insertion scripts use their own approved plan's endpoint and
genesis preflight before any provider or submission; that signed, plan-scoped
boundary must not be replaced by the shared-stack wrapper.

`deploy/standalone/compose.yml` remains the repo-owned **isolated** qualification
stack, with its own project, volumes, private indexer credentials, and loopback
ports. It must not be run as `midnight-network` or against the owner's volumes.
Its existing image digests and proof-parameter policy remain unchanged until
separately validated; the Compose services carry an isolation label for
ownership checks. For an isolated stack, set `TR_NODE_PORT`, `TR_INDEXER_PORT`,
`TR_PROOF_PORT`, and `TR_EXPECTED_PROOF_VERSION` before the preflight. If its
ports or chain are incompatible with the shared stack, use an explicitly unique
project and state, not a shared-project restart. The version preflight is
read-only and does not start or inspect containers.

The installed-identity guard requires exact published identity versions and
rejects local `file:` tarball overrides. Its unit tests and installed-package
check pass for six identity packages at Compact runtime 0.21.0.
The `@midnight-ntwrk/trust-registry-integration` `test:light` check also
passes with the exact native Compact 0.36.0 compiler installed: it compiles
the VC composition fixture and checks the credential/presentation envelope
relation, including claim-root, issuer-method, and schema mismatches. It does
not exercise a deployed Ledger 9 registry or a VP actor journey. At local head
`6b53aac0`, the integration package typecheck has zero diagnostics and the full
Vitest integration suite passes 52 files, 376 tests with two skipped. This is
simulator/fixture validation, not a deployed or finalized end-to-end result.
The two skipped cases remain unqualified.
The client package also typechecks and its full Vitest suite passes eight files
and 65 tests with asynchronous simulator reads and bundle verification. The
contract package now typechecks and its full Vitest suite passes eight files
and 97 tests. These are simulator and fixture checks, not a deployed Ledger 9
flow.
The CLI workspace now awaits replayed governance operations and snapshot
projection. Its full suite passes five files and 32 tests. Epoch preparation
waits for the harness's asynchronous evidence-verifier bootstrap, preventing
a first-epoch signature from racing a governance-sequence change. The full
integration suite still passes 52 files and 376 tests, with two skipped.
The API production build awaits workspace mutations and signed-intent
preflight. At local head `03091abf`, API build, lint, and full typecheck pass.
The full API suite passes 43 unit files (332 tests) and 17 integration files
(111 tests). The migration updated historical test callers for asynchronous
Ledger 9 simulator and CLI operations, tagged runtime verifying keys, and a
finalized v9 transaction fixture. These remain fixture and mocked-provider
checks, not deployed actor qualification.

The official [Ledger 9 upgrade guide](https://docs.midnight.network/relnotes/ledger-9)
is the compatibility source. The
[Midnight.js 5 notes](https://docs.midnight.network/relnotes/midnight-js/midnight-js-5-0-0)
cover ESM, provider `config`, era-aware types and removal of `setNetworkId()`.
The [indexer 4.4.101 notes](https://docs.midnight.network/relnotes/midnight-indexer/midnight-indexer-4-4-101)
require a new index for older 4.3 data. Exact Docker image digests are in
`deploy/standalone/compose.yml`; `node scripts/check-standalone-compose-render.mjs`
validates the base and offline configurations without starting containers.

The registry contract and trust-state model do not require VC. VP-based
application evidence does. The API now resolves actor authentication and
mutation-intent keys through the DID-owned document and codec types, not the
VC proof adapter. It still requires subject, controller, relationship,
positive DID version, native Jubjub key type, and prime-order key checks.
The VC release gate applies only to VP evidence journeys, not basic DID
challenge-response. The standalone key-resolution tests pass, but neither
they nor the simulator integration suite qualify deployed actor journeys.

The local VC trial source was [PR #755](https://github.com/midnightntwrk/midnight-verifiable-credentials/pull/755)
at `dad8b2cae38c9971adb43d124ead1281b021416b`, merged on 2026-11-17.
Its Nix `npm-artifacts` target built three historical 0.4.0 trial tarballs.
The obsolete local copies and their smoke-install path have been removed.
The consumed VC packages,
`credential-compact` and `credential-did-midnight`, are now pinned to published
`1.0.0-rc1` versions with registry-resolved lockfile integrity. The published
`credential-model@1.0.0-rc1` is part of the cohort but is not a direct Registry
dependency. Exact-version minimum-release-age exceptions expire after
2026-11-24 UTC; the seven-day default remains in force.

On 2026-11-17, `pnpm install --frozen-lockfile --ignore-scripts`, the installed
identity runtime gate (23 tests), documentation and security-script checks,
and `integration:prebuilt` passed with the published VC RC1 pins. The prebuilt
run found 66 full proof circuits and passed 378 integration, 111 API, 72
applicant-portal, and 31 admin-console tests plus signed simulator journeys.
This removes the VC tarball portability blocker, not the need for packed-package
validation or finalized on-ledger actor evidence.

Current compile evidence is limited to `compact:light`. The test simulator now
awaits generated `initialState` and impure circuits, serializes calls, and
labels each call with its actual circuit ID. Its source-only TypeScript build
check passes, and the full contract suite passes 97 cases, including
deployment-bound replay, evidence-verifier-key lifecycle, VC-authority-key
lifecycle, and verifier proposal evidence. The latter uses a serialized
test-only raw-circuit entry point rather than mutating simulator context.
The historical registry test now awaits Ledger 9 reads and circuit results,
including expected rejection paths. This is a source migration, not a
deployment qualification pass. No new
proving/verifier keys or deployed transactions have been generated.

The integration source now uses the deployment provider's `config.networkId`
instead of the removed process-global network ID for the pinned deploy path.
The simulator harness now exposes an awaited bootstrap promise for its
evidence-verifier registration and awaits the Ledger 9 evidence-verifier key
rotation/status circuits. The focused DID-key lifecycle suite passes all five
cases. The remaining harness methods and integration callers now await the
Ledger 9 simulator; the full integration typecheck and test suite pass.
VC authority-key registration and suspension now await the same bootstrap,
ledger reads, quorum signatures, and simulator circuits. The focused Ledger 9
authority-key harness test passes registration, status transition, and a
wrong-registry domain rejection; the broader decision-evidence suite now also
passes with awaited circuit results.
The governed threshold-policy revision path now awaits the Compact result
before changing its local policy record and awaits the subsequent
evidence-verifier registration. A focused Ledger 9 test confirms policy
version progression, two governance actions, and the active replacement key.
External-quorum policy revision and recovery now pass their integration tests.
The maintainer onboarding path now awaits evidence validation, governed
proposal, authorization, and activation. Atomic recovery awaits its active
membership and policy prechecks, then updates the local policy record only
after the recovery circuit resolves. Focused Ledger 9 simulator tests cover
successful onboarding, insufficient recovery quorum, and an atomic recovery
that reduces active maintainers and revises the policy. They do not establish
deployed-chain finality.
Issuer onboarding now awaits application evidence, proposal, authorization,
and activation; issuer suspension, revocation, and archival also await their
governed circuits. A focused Ledger 9 simulator test checks all six status
transitions and sequence increments. It is simulator evidence only, not a
deployed issuer journey.
Verifier onboarding now awaits application evidence, proposal, authorization,
and activation, followed by awaited suspension, revocation, and archival.
The focused Ledger 9 simulator test confirms state and governance-sequence
changes across those actions; it is not a deployed verifier journey.
Auditor onboarding and recognition proposal/decision/status methods now await
their Ledger 9 simulator calls. Separate focused tests cover active, suspended,
revoked, and archived states for each role. Recognition's signed external
authority assertion is a distinct integration path, now covered by its own
passing integration test.
Epoch publication, witness readback, and evidence-bundle assembly now await
the Ledger 9 simulator. Focused issuer, verifier, auditor, and recognition
tests verify active decision bundles against their published epoch roots and
maintainer signatures; publishing an epoch adds a governance action. The
integration harness and its historical callers now typecheck and pass in the
full integration suite. These are simulated epochs, not finalized chain
receipts.
The broad local simulator suite now passes all 36 cases with awaited Ledger 9
governance and readback, including negative quorum, lifecycle, format, and
tampered-evidence paths.
The simulator-backed VC decision-evidence suite now passes both issuer and
unchanged-grant tests. Its compiled VC consumer uses Ledger 9 named circuit
contexts and awaited circuit results; it verifies installation, revocation,
replay, schema proof, and verifier request checks. This is local simulator and
compiled-circuit evidence, not a finalized deployment receipt.
Readback-only paths use their explicit network and receipt. A strict helper
encodes the tagged Compact runtime Schnorr verifying key into the policy's
canonical `0x`-prefixed hex; its focused tests and integration lint pass.
This is only a partial migration: production integration source and standalone
operator scripts no longer import the removed global network-ID package.
Verifier-key insertion rejects a provider configured for a different approved
network before reading the deployment or mutating its journal. Integration
test fixtures no longer use the global setter, but other SDK 5 transaction and
state-read APIs still require changes. The simulator client now awaits
ledger reads and bundle context; its source-only build, focused async tests,
and lint pass. Integration callers now use asynchronous results and the
integration package typecheck passes; these source edits are not deployment
evidence.

The public, local and staged deployment journal wrappers now compare the
provider's configured network with the approved network before reserving an
attempt. Their focused suite passes 11 tests without the removed global
network-ID package. The public-deployment policy suite also passes 26 tests
with explicit provider configuration and a v9-era fixture adapter; it uses
placeholder verifier-key bytes for policy branching, not genuine serialized
v9 key material. The staged-reconciliation suite uses the explicit local
network input and no global setter.

The finalized deployment reader now rejects non-v9 serialized contract state
and decodes v9 bytes through Compact runtime 0.21 before reading the ledger or
maintenance image. Its focused suite passes six tests, including the wrong-era
case. Two image tests remain skipped without an exact-source verifier-key file;
the passing read tests do not qualify verifier-key image readback.

The local pinned submission adapter now requires a finalized Midnight.js 5
handle, rejects a non-v9 era, decodes the Ledger 9 transaction ID, and declares
only `v9` support. The issuer proposal's guarded provider wrapper preserves
that declared era. Their focused suites pass 31 tests for guard ordering,
transport failure, finality, and ambiguity. Successful submissions in these
tests use mocked valid handles, not a proven and bound Ledger 9 transaction;
real submission and finalized readback remain unqualified.

Verifier-key insertion now consumes the Ledger 9 maintenance result's public
finalized record, recognizes the SDK's failed-insertion error code, and rejects
an older-era record without writing a success receipt. Its provider preflight
decodes v9 serialized contract state before checking the absent key slot and
authority counter. The journal, preflight, and reconciliation focused suite
passes 14 tests. These are mocked SDK submissions; no actual verifier-key
maintenance transaction or independently finalized image was observed.

Committee maintenance preparation, submission, and reconciliation now use
Ledger 9 tagged signature/verifying-key types. Submission seals the prepared
transaction as a v9 unproven SDK handle and compares provider `config.networkId`
with the approved network. Their three focused suites pass 44 cases, including
the reconstructed update hash, explicit network mismatch, journal reservation,
and ambiguous recovery states. The wrapper test mocks SDK submission; it does
not prove a real transaction, wallet balance, broadcast, or finalized committee
transition.

Docker Desktop subsequently became responsive. The three digest-pinned
containers are running under the dedicated `tr-standalone-ledger9-local`
Compose project; the node and indexer are healthy. The local node returns
genesis `0x823383ec0302be8417cfcbcc62f21df08f4047bca37aaea89e3f54b550ebae1d`
at height zero, and the indexer independently returns the same height-zero
hash through `/api/v4/graphql`. The indexer returned an indexed block at
height 36 with protocol version `2001100` during this probe. This genesis is
specific to these local volumes and is not a checked-in network constant.
The node's `midnight_ledgerVersion` RPC returned `1.0.1`, so that RPC is not
being treated as an attestation of the documented `9.1.0.1` crate version.
No contract state, transaction, finalized readback, or Trust Registry proof
has yet been observed on this stack.

Docker Desktop did not publish ports from the original single `internal: true`
network. Compose now retains an internal ledger bridge and adds a separate
project-private host-access bridge for the three infrastructure services;
only `127.0.0.1:29944`, `:28088`, and `:26300` are published. This makes the
infrastructure containers egress-capable, not an egress-denied actor test.
The proof server uses the existing read-only parameter cache, with the 2p15
and 2p16 files matching the SHA-256 values recorded in VC PR #755. Service
startup does not establish parameter completeness for every TR circuit.

For this historical isolated stack, `pnpm check:ledger9-local-stack` requires
the three `TR_*_PORT` overrides and `TR_EXPECTED_PROOF_VERSION=9.0.0`; the
current defaults attach to the owner's shared stack instead. Set
`TR_EXPECTED_GENESIS_HASH` to an independently approved value if the check must
also enforce a particular local chain. The command does not sign
or approve genesis, exercise a proof, deploy a contract, or establish
transaction finality. It is intentionally not part of offline CI.
After an approved Docker Desktop restart, the dedicated node and proof-server
containers were restarted without deleting their volumes. The live
`pnpm check:ledger9-local-stack` probe passed again: node
`2.1.101-86774edf`, runtime protocol `2001100`, matching node/indexer genesis
`0x823383ec0302be8417cfcbcc62f21df08f4047bca37aaea89e3f54b550ebae1d`,
indexed height 605, and reachable proof server. This is infrastructure
readiness, not a deployed registry transaction or finality claim.
Offline source validation at `e7e02633` now passes the repository lint gate,
127 standalone-topology cases, 244 local-ledger preflight cases, and strict
security-script typecheck. The standalone install policy is tested against
the checked-in Ledger 9 Compose project name. The Ledger 9 development stack
has a project-private host-access bridge for loopback forwarding. The topology
observer now verifies both named bridges and reports `internalNetworkOnly: false`;
offline qualification still rejects that development topology. These source checks do not prove
the currently unresponsive live stack or a deployed actor journey.
The separate `test:demo-smoke-scripts` gate now passes 254/254 cases after
migrating its historical adversarial and demo fixtures to awaited Ledger 9
harness, simulator, snapshot, and client operations. This includes the 40
Compact adversarial cases, six recognition-intake negatives, recognition and
role lifecycle cases, and governed API/signature cases. The denial helper
covers live-scope reuse, archive quorum, and archived-proposal trust rejection.
These are source and simulator evidence only. An isolated policy-replay matrix
now awaits and verifies its old-policy rejection, historical evidence, and
revised-policy role cases. The full governed demo now passes with awaited
proposal, membership, VC consumer, temporal, and policy-recovery operations.
The strict adversarial parity check reports 198 demo cases, 198 isolated
cases, and no missing cases or issues. Its seven threshold-history failures
were traced to an isolated fixture that read asynchronous Ledger 9 state
before setup completed; all seven pass after awaiting the fixture and client
checks. `pnpm ci:lint` also passes at this local tree. These remain simulator
and source checks, not proof-artifact, finalized deployment, or actor-journey
evidence. No failed case was skipped or reclassified as a pass.
The TRQP and OpenID Federation adapter test fixtures now await Ledger 9
authorization, evidence, and ledger reads. Their focused suites pass 15 and
10 tests respectively; the full workspace typecheck passes all ten runnable
package tasks. Strict security-script typecheck, 244 local-ledger preflight
tests, and 127 standalone-topology tests also pass at this local tree. These
gates do not establish a responsive node or deployed-chain finality.
The auditor-admission demo host now awaits CLI workspace construction before
reading its registry ID or passing the workspace to the pending-application
port. Both live-host integration files pass all four cases; the applicant
portal suite passes 13 files and 72 tests. A direct, non-destructive Turbo
`test:light` run passes all ten package tasks (nine from the local cache).
That earlier browser attempt was blocked by missing source-matched Compact
output and an unresponsive Docker daemon. Both prerequisites were subsequently
restored; its earlier result is not the current qualification state.
An isolated checkout at `7ff17a86` subsequently built source-matched
skip-ZK Compact output and installed the frozen lockfile offline using the
same ignored VC tarballs. Its pinned Playwright Chromium headless shell ran
all 98 browser cases successfully after the browser fixtures awaited Ledger 9
workspace, maintainer-policy, evidence, signature, execution, and ledger-read
operations. The suite covers both portals, packaged-host DID sign-in, local
workspace handoff, governance recovery, layout, accessibility, and offline
egress controls. It is browser/fixture evidence only: no proof, deployed
contract, finalized transaction, or live actor journey was observed. The
active migration checkout still preserves its partial generated output; the
isolated validation checkout and browser cache are disposable.
The standalone headless entrypoints also now await CLI workspace creation.
`demo-auditor-admission` application and smoke commands, the signed local
journey, the packaged off-chain DID CLI journey, and the DID session journey
all pass against the built Ledger 9 simulator packages. A CLI nonce-schema
test now first proves its baseline workspace is valid; previously it spread
an unresolved Promise, making its negative cases vacuous. Its focused suite
passes 18 tests. These commands use fixtures and simulated finality, not a
deployed contract or live-chain receipt.
The packed recognition journey now awaits Ledger 9 maintainer setup, governed
accreditor anchor, proposal signatures, ledger/evidence reads, and current
decision verification. It passes its VP accreditation, retained proposal
signature, loopback evidence API, and suspension assertions. The signed
membership journey now passes separately for issuer, verifier, auditor, and
maintainer with awaited 2-of-3 governance, VP intake, epoch publication,
historical readback, and file-backed process restart. These are still
simulator/loopback journeys; the node did not finalize any of their actions.
The compiled VC consumer fixture now awaits Ledger 9 constructor, named
circuit contexts, signer installation, proof assertions, and ledger reads.
Its issuer/verifier positive and substitution, rollback, and revocation
negative checks passed at that point with local VC 0.4.0 trial packages.
That result was not proof from a deployed registry or a portable
packed-package result.
The public-package consumer smoke also awaits issuer/verifier governance,
evidence reads, and client verification; its positive checks and wrong-resource
rejection pass against the local workspace build. Packed-tarball validation
still requires a source-matched release candidate, not this partial build.
An isolated source-matched skip-ZK build produced ten Trust Registry tarballs.
At the time, normal packed smoke stopped at npm install because the 0.4.0 VC
trial package was not published. The local trial install path is now removed.
At `34c3155f`, that isolated smoke installed all ten Registry tarballs and
passed the compiled VC consumer plus issuer, verifier, auditor, maintainer,
and recognition actor journeys. It used skip-ZK output and local VC trial
tarballs, not full proving artifacts, deployed transactions, or published
VC packages.
At `9e75d8fd`, the non-destructive workspace `test:light` and `typecheck`
Turbo gates passed all ten runnable package tasks each, without cache hits.
The contract suite reported 97 tests, the CLI 32, and the API 387. These
source and fixture checks do not qualify local-node finality or deployment.
At `20db73ea`, the artifact-policy suite passed 88 cases, including rejection
of local VC tarball overrides in release-manifest mode. The strict adversarial
parity check passed 198/198 extracted cases with no missing IDs. Those checks
did not replace deployed proof or finalized actor evidence. At the time,
`@midnight-ntwrk/credential-compact@0.4.0` was not on npm, so that historical
trial required the local tarballs. The published `1.0.0-rc1` migration above
supersedes that package-portability limitation.

At the current local migration tree, full Compact 0.36.0 key generation first
exposed a ZKIR v3 cost-model failure for `transientHash<JubjubPoint>` in
`proposeMaintainerMembership`. The maintainer key commitment now uses a
domain-separated persistent hash of the point's X and Y coordinates; focused
tests assert coordinate sensitivity and pin the resulting Ledger 9 proposal
payload hash. This changes the proposal transcript and verifier keys: Ledger 8
signatures and key material must not be reused for a Ledger 9 deployment.
`zkir-v3 mock-compile-many` then passed all 66 circuit inputs, and the full
Compact build produced 66 proof circuits, 132 nonempty prover/verifier keys,
and 132 nonempty ZKIR/BZKIR files. `pnpm contract:check-full-artifacts` passed
against the source-matched outputs. `pnpm integration:prebuilt` passed with
378 integration, 111 API integration, 72 applicant portal, and 31 admin
console tests, plus the signed role journeys and final full-artifact check.
After installing the pinned headless Chromium, `pnpm test:browser` passed all
98 Playwright cases at this tree. The first attempt failed before any browser
test ran because that executable was absent; it was an environment setup
failure, not an application failure. These are local full-artifact and fixture
results, not proof of a deployed contract, finalized transaction, or live
actor journey.

The development-only `local-smoke-provider` also needed the testkit-js 5.0.0
wallet API: `MidnightWalletProvider.withWallet` now receives the complete
`WalletSeeds` object, not separate shielded and DUST secret keys. A read-only
live probe then synchronized the public local test wallet and observed
spendable NIGHT and DUST on this dedicated Ledger 9 stack. It did not open a
maintenance key, submit a transaction, deploy the registry, or approve genesis.
The provider set also now includes Midnight.js 5's required network ID and
3600-second transaction TTL; a second live probe confirmed the constructed
provider exposes those values without making a write.
Compact 0.36 also emits `compiler/contract-manifest.json`. The keyless ZKIR
bundle and release-candidate inventory now retain and hash that file as a
required source-bound asset; silently dropping it would prevent the Ledger 9
ZK-config provider from checking the generated artifact set. This local
packaging fix does not itself establish a portable release bundle.
Full-package candidate validation also rejects a contract archive without
the Compact manifest before treating its key inventory as complete.

A single approved development-only staged deployment on a separate, shared
Ledger 9 local chain reached the node but was rejected with `1010: Invalid
Transaction: Custom error: 110` (`VerifierKeyNotSet`). No submitted receipt was
recorded and deployment remains unverified; the attempt journal remains
quarantined for read-only reconciliation. The generated Compact constructor inserted all 66
operation slots, while the staged `CompiledContract` supplied only the selected
initial verifier key. Ledger 9 rejects the remaining blank slots. The staged
bootstrap adapter preserves constructor data, maintenance authority, and
balances but carries only the selected operation in the initial contract state.
A real-constructor regression test
checks the serialized operation set, and an offline Midnight.js 5 unproven
deploy build observed one operation with a nonempty verifier key. This is not
evidence of a successful live deployment or permission to retry the failed
attempt. The code mapping is documented in the
[Midnight node error codes](https://docs.midnight.network/nodes/error-codes).

On the owner's current shared chain, a fresh private pin at indexed block 362
identified the chain independently of its reusable development genesis. A new
source-matched ten-package manifest at signed revision `e51c6de9` verified all
66 verifier keys. One separately journaled, development-only staged deployment
then returned contract address
`0xf80638c64dcf63138b222426549bedb122673391b414658854f2a04a92b5be09`
at block 505. The node independently reports the receipt's block hash at
height 505 and a finalized head beyond it; the API v4 indexer reports one
`ContractDeploy` action for that address in the same block. The SDK receipt
`txId` is the second value in that `RegularTransaction.identifiers` array;
the separate indexer `Transaction.hash` has a different value and must not be
compared to the receipt ID. This independently links the receipt ID, block,
and deployed address without equating the two hash fields. Read-only journal
reconciliation reports `staged-bootstrap-pending` with a finalized contract
image, not completed key installation or a qualified registry. The repeatable read-only
`scripts/observe-local-deployment-inclusion.mjs <private-plan.json>` check
requires the finalized node block, API v4 block, receipt identifier, and
`ContractDeploy` address to agree. It describes the indexed transaction as
indexer-reported, not as a cryptographic inclusion proof. Run it through the
pinned `localnet:run` wrapper; it never submits a transaction. The ignored
`artifacts/ledger9-current-chain-smoke-state` journal and
`artifacts/ledger9-current-chain-pack` manifest must be preserved; never replay
this deployment. No additional shared-chain write was approved in this step.
The next-key planner subsequently read the current finalized image without
reserving or submitting anything. It found one installed key of 66, selected
`activateAuditorAuthorization` as the first missing release-catalog key, and
confirmed maintenance authority counter zero. A private insertion plan is
saved beside the deployment journal, but its per-circuit journal does not
exist. Installing that key or the remaining 64 would be additional
shared-chain writes, not covered by the one-deployment approval.

## Execution order

1. Keep the `ledger8` source branch only as a historical reference. Ledger 9
   replaces the default standalone Compose stack; there is no parallel Ledger 8
   runtime profile. Remove old node/indexer volumes only after confirming they
   belong to this project and no active container uses them. Never reuse an
   older database with indexer 4.4.101.
2. Qualify the three official images in the default Compose file. The local
   `system_version`, runtime `specVersion`, and node/indexer genesis and
   progress checks now pass. Confirm the exact ledger crate provenance through
   the image build inventory rather than treating `midnight_ledgerVersion` as
   that value; still verify deployed contract-state decoding before application calls.
3. Consume published, exact-version DID 1.0.0-rc1 packages. Complete API
   actor-authentication qualification with the DID-owned key lookup and
   preserve key relationship, controller and origin checks. Core actor
   authentication can qualify before the VC migration. VP evidence journeys wait for a tested
   Ledger 9 VC core and DID binding from
   [VC #754](https://github.com/midnightntwrk/midnight-verifiable-credentials/issues/754)
   and PR #755. Do not combine VC 0.3.0/runtime 0.16.0 with
   runtime 0.21.0 or weaken the installed-runtime guard.
4. Move all core dependencies, workspace overrides, compiler/runtime pins,
   Nix hashes and lockfile together. Replace Midnight.js 4 provider and global
   network ID APIs with the version 5 configuration model. Run a frozen install,
   strict type checks, package guards, DID composition and packed consumers.
   Run VP-specific checks when the compatible VC cohort is available.
5. Recompile the contract with Compact 0.36.0 and regenerate managed output,
   ZKIR, proof parameters and key inventory for the exact source head. This
   changes verifier keys. Either use an approved maintenance transition for an
   existing deployment or deploy a new contract; never attach the new keys to
   an old deployment without that transition.
6. Run fixture CI, then a separate deployed local actor qualification: signed
   genesis, DID session, VP evidence, issuer/verifier/auditor submissions,
   maintainer votes, finalized readback, restart and recovery. Record the exact
   source, image, genesis and contract identities. Browser/CLI fixture tests
   alone are not deployment evidence.

The work is tracked under [#292](https://github.com/midnightntwrk/midnight-trust-registry/issues/292):
[#319](https://github.com/midnightntwrk/midnight-trust-registry/issues/319)
infrastructure, [#320](https://github.com/midnightntwrk/midnight-trust-registry/issues/320)
SDK/DID/VC, [#321](https://github.com/midnightntwrk/midnight-trust-registry/issues/321)
Compact artifacts, and [#322](https://github.com/midnightntwrk/midnight-trust-registry/issues/322)
end-to-end qualification.
