# Ledger 9 migration plan

Status: local migration in progress. This document is not a deployed or release
qualification claim. The historical Ledger 8 source is the `ledger8` branch at
`5abc1575922d3f0cc7234f5f1d4c0a77e045fcfd`.

## Selected official matrix

| Component | Selected version | Current migration state |
| --- | --- | --- |
| Node | 2.1.101 | Live loopback check passes with `system_version` `2.1.101-86774edf` and runtime `specVersion` `2001100` |
| Ledger | 9.1.0.1 node; 9.1.0.2 client | Official node cohort and protocol-version evidence; no independent crate-version attestation from RPC. Client `@midnightntwrk/ledger-v9` 1.0.2 now matches the tested patch cohort |
| Indexer standalone | 4.4.101 | Live indexed block and matching genesis check passes |
| Proof server | 9.0.2 observed | Live loopback/version check passes; corrected Registry governance and issuer fixture calls proved, submitted, and finalized on the shared chain |
| Compact compiler | 0.36.0 retained | Full source-matched compile generated all 66 circuits and prover/verifier keys. The official 0.36.1 patch does not require rebuilding this deployed contract; a future recompile needs separate verifier-key qualification |
| Compact runtime | 0.21.0 | Installed with exact DID RC1 and VC RC1 artifacts; simulator and deployed fixture issuer lifecycle pass, live VP journey unqualified |
| Midnight.js / testkit-js | 5.0.1 | Exact tested client patch installed; a fresh fixture issuer proposal finalized, broader actor journey unqualified |
| Compact.js | 3.0.2 | Exact tested client patch installed; simulator, client, harness, and integration tests use awaited circuit/read APIs |
| `@midnightntwrk/ledger-v9` | 1.0.2 | Client fee calculations aligned with the node's Ledger 9.1.0.1 rules |
| `@midnightntwrk/onchain-runtime-v4` | 4.0.2 | Exact tested client patch installed |
| Midnight DID | exact 1.0.0-rc1 cohort | Published and installed locally under four dated, exact-version age exceptions |
| VC Compact and DID binding | published 1.0.0-rc1 | Exact versions installed from npm; packed Registry consumer and fixture journeys pass, deployed VP actor journey unqualified |

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
`2001100`, matching node/indexer genesis and latest indexed block hash, an
indexed height no later than the node-reported finalized head, and proof-server
`9.0.2`. The WebSocket URL in its output is derived from the
verified API v4 HTTP endpoint but is not itself handshake-tested. A passing
attach is node-consistency evidence only, not independent finality, a registry deployment, or
proof-submission test.
The shared chain is a multi-user development network. Sessions must preserve
separate wallets and journals, pin a non-genesis checkpoint before relying on
prior deployment records, and treat unrelated transactions or changing head
height as normal. Never reset or restart it to make a Registry test pass.

After attaching, the read-only actor-state command accepts a contract address
and an optional issuer label. It requires the expected genesis and non-genesis
checkpoint pin; unlike the fixture demo it reads the finalized deployed
ledger. With this checkout's ignored private pin, the development smoke
registry can be inspected without starting a wallet or submitting a call:

```sh
node --env-file=artifacts/ledger9-current-chain.env scripts/read-ledger9-registry.mjs \
  --address 0xf80638c64dcf63138b222426549bedb122673391b414658854f2a04a92b5be09 \
  --issuer-label issuer:local-development-fixture:v1 \
  --manifest artifacts/ledger9-current-chain-pack/release-manifest.json
```

The optional `--issuer-resource-id` takes a canonical
`tr:issuer-resource:v1:<64 lowercase hex>` ID together with `--issuer-label`.
It compares that ID's commitment with the finalized issuer record and reports
`canonicalResourceIdCommitmentMatches`. This is a read-only preflight, not a
decision verdict. The reader rechecks the private genesis and non-genesis
checkpoint at every finalized-state query, so a changed shared development
chain cannot pass only because an earlier discovery succeeded. This still
trusts the pinned local node; it is not independent finality. The output
reports the observed chain identity, finalized block hash, verifier
key count, governance counters, active maintainer count, required epoch-publish
signer count, and selected issuer lifecycle. The signer count is a policy
threshold, not proof that those signers or their private keys are available. It does not
verify that an issuer supplied live DID/VP evidence. With `--manifest`, it
requires the complete generated circuit catalog and every finalized verifier
key hash to match the selected source-matched release manifest; it reports that
manifest's source revision. Without `--manifest`, the numeric key count alone
does not establish a source match. This local manifest comparison is not an
independent signature or release approval check. The output includes the
finalized `publishedEpochCount` and current epoch roots. An active fixture
issuer does not satisfy the governed VP decision-evidence path merely because
a registry snapshot epoch has been published.
The command also exposes the finalized issuer status-policy binding commitment;
the caller must independently match it to a governed VC-owned status binding.

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
In a checkout retaining full generated Compact artifacts, use
`pnpm integration:prebuilt` and `pnpm typecheck:prebuilt` for non-destructive
validation. The ordinary root `typecheck` target follows Turbo build
dependencies and recompiles the 66 circuits; light targets replace the full
distribution output. Neither is appropriate for an artifact-bearing checkout.
The `@midnight-ntwrk/trust-registry-integration` `test:light` check also
passes with the exact native Compact 0.36.0 compiler installed: it compiles
the VC composition fixture and checks the credential/presentation envelope
relation, including claim-root, issuer-method, and schema mismatches. It does
not exercise a deployed Ledger 9 registry or a VP actor journey. At this local
migration head, integration package typecheck has zero diagnostics and the full
Vitest integration suite passes 52 files and 378 tests. This is simulator and
fixture validation, not a deployed live DID/VP end-to-end result.
The client package also typechecks and its full Vitest suite passes eight files
and 65 tests with asynchronous simulator reads and bundle verification. The
contract package now typechecks and its full Vitest suite passes eight files
and 99 tests. These are simulator and fixture checks, not a deployed Ledger 9
flow.
The CLI workspace now awaits replayed governance operations and snapshot
projection. Its full suite passes five files and 32 tests. Epoch preparation
waits for the harness's asynchronous evidence-verifier bootstrap, preventing
a first-epoch signature from racing a governance-sequence change. The full
integration suite passes 52 files and 378 tests at this local head.
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
This removes the VC tarball portability blocker, but does not establish
finalized on-ledger actor evidence.

At local head `4afefc41`, the full-artifact check found all 66 proof circuits,
the ten Registry package-content checks passed, and a separate clean-install
smoke from ten freshly packed tarballs passed the Ledger 9 VC consumer fixture
and signed issuer, verifier, auditor, maintainer, and recognition fixture
journeys. The tarballs were built in an exclusive temporary target rather than
replacing the source-matched current-chain pack. This closes the packed-package
portability check for the published VC RC1 pins, but none of these fixture
journeys submitted to or read finalized actor state from the shared chain.

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
confirmed maintenance authority counter zero. A private insertion plan was
saved beside the deployment journal, but its per-circuit journal did not yet
exist. Installing that key or the remaining 64 required separate approval
because the one-deployment approval did not cover further shared-chain writes.

On 2026-11-17, the operator separately approved installation of the remaining
65 verifier keys on this same shared development chain. The repo-owned attach
check confirmed the pinned genesis and non-genesis checkpoint before each
sequential submission. Each accepted insertion was journaled per circuit and
required finalized readback before the next. Two submissions returned the
node's `isInvalid` rejection without a receipt. Their reservations and logs
were preserved, finalized reads showed the corresponding keys absent, and
private rejection-evidence records were written before retrying each once in
a fresh wallet session. Neither rejected attempt was treated as a successful
transaction or silently replayed. A separate read-only check at indexed
height 1878 confirmed all 66 verifier-key hashes equal the source-matched
manifest at `e51c6de9`, the maintenance counter is 65, and the latest
insertion is verified. The finalized image hash was
`0xbe4737bd4d96c7b2ffcb75015b1fe94fd19bdecc9e97a75f0b41b9b8a3d26056`.
Private journals and recovery evidence remain under the ignored
`artifacts/ledger9-current-chain-smoke-state/` directory. This is a
development-only bootstrap with the single-key maintenance authority; it
does not qualify actor journeys, an approved maintenance transition, or a
release.

A read-only reconciliation on the pinned multi-user chain at indexed height
2026 matched all 66 verifier keys and maintenance counter 65. At that point,
the finalized ledger had governance action count 1, one active maintainer,
zero evidence-verifier keys, and zero active issuer, verifier, auditor, or
recognition entries. The issuer path first required a governed
evidence-verifier-key registration under a DID distinct from the maintainer.

One development-only evidence-verifier registration was prepared against this
finalized baseline with a distinct verifier DID and a locally verified
deployment-bound maintainer signature. The first reserved attempt stopped in
Midnight.js 5 transaction construction because the new wallet session's
in-memory private-state provider lacked `trustRegistryPrivateState`. SDK source
places that failure before unproven transaction creation. Its reservation and
private pre-broadcast evidence were retained. A separate one-shot retry
initialized the empty contract private state, then reached the proof provider;
`proveTx` failed when proof-server `/check` returned HTTP 400. Midnight.js 5
calls `proveTx` before wallet balance and `submitTx`, so that failure also
preceded broadcast. The second reservation and proof-failure evidence remain
quarantined. A subsequent pinned-chain finalized read still found the same
governance sequence and zero evidence-verifier keys. No transaction receipt
exists for either attempt; do not retry or claim actor qualification until the
proof check is diagnosed and a new one-shot plan is reviewed.
A proof-only diagnostic using the full source-matched compiled contract, with
`submitTx` replaced by a hard-failing local stub, reproduced the same `/check`
HTTP 400. A private response capture showed the cause: unused maintainer
signer slots carried zero-valued points, which the Ledger 9 proof server could
not decode as `JubjubPoint` even though the circuit ignores inactive slots.
The TypeScript bundle builder now retains zero key IDs but pads point fields
with a deterministic valid prime-order point. Its regression test and the
99-test contract suite pass. A subsequent full-contract proof-only call passed
proving and balancing and reached the hard-failing broadcast guard.

After confirming both older reservations failed before broadcast and finalized
state still lacked the key, a new single-use private journal submitted the
corrected development call. Transaction
`007218fa13ba1e08992d672f37bfed0e414fa5bbd0776442b23549ebd3cddd7ca1`
finalized at registry
`0xf80638c64dcf63138b222426549bedb122673391b414658854f2a04a92b5be09`.
Readback showed governance action count 2 and one active evidence-verifier key.
The failed reservations, new receipt, and proof response remain private under
the ignored smoke-state directory. This is one development-chain governance
action, not a live DID/VC evidence journey or release qualification. The public
test wallet is shared with other sessions, so every actor write needs a fresh
one-shot journal and finalized-state reconciliation. A repeatable actor harness
should use an exclusive funded session wallet instead.

The next issuer-intake preflight used the finalized evidence-verifier key,
fixture-only evidence commitment, and separate issuer DID. The deployed
`proposeIssuerAuthorization` circuit passed a full-contract proof and wallet
balance, then reached a hard-failing `submitTx` stub. A separately journaled
one-shot call then finalized the proposal as transaction
`006bb3b322cee279acf2407a8752d1d6fe735fa5c3c745dcd0468e0adec92a900f`.
The proposed record retained the fixture evidence commitment. The subsequent
`authorizeIssuerAuthorization` and `activateIssuerAuthorization` calls each
passed proof-only preflight, then finalized in distinct one-shot journals as
transactions `00c6517d8bbe3f9f2a0296f725bd0c5432ba8665d37ca502324c35b9dd859ff50f`
and `00b2d3ed1ae43e16a5a8bb13d84a833759bd435ca6317ee1bdb72326c11efbf9b4`.
An independent read-only ledger check found governance action count 5, one
active issuer, one active evidence-verifier key, and all 66 verifier keys.
These are deployed local fixture-backed governance transitions, not a live
DID/VP-verified issuer application or a release qualification result. Verifier,
auditor, recognition, restart/restore, and ambiguous-submission journeys remain
unqualified on this chain.
At indexed height 2744, the pinned read-only Registry command with the
source-matched `e51c6de9` manifest confirmed exact equality for all 66
finalized verifier-key hashes, maintenance counter 65, and the active fixture
issuer. A separate finalized read found `epochCommitmentCount` zero, so no
accepted decision epoch exists on this chain for the governed VP eligibility
reader at that point. These reads did not submit a transaction or qualify live
VP intake.
The integration package now exports a non-fixture canonical application VP
body adapter. Its signed-body, DID-method, presentation-context, and
DID-signed status-attestation fixture tests pass, but the host still must
select an exact governed issuer `schema` grant matching the signed credential
schema ID and full issuer-scope commitment, authenticate finalized decision
evidence, and supply a live VC-owned status authority. Do not treat the
adapter or its fixture tests as deployed actor evidence.
The canonical body also passes the qualified API intake callback and produces
a verifiable evidence signature in a local fixture test. This verifies the
adapter-to-intake boundary, not a live API deployment or chain submission.
On the shared Ledger 9 development chain, a separate one-shot maintainer
transaction published a **registry snapshot** epoch after proof-only validation:
transaction `00b4e26350468604748b039bac5d424401eb7b519afb2fae03aa68be7526d3b513`
at contract `0xf80638c64dcf63138b222426549bedb122673391b414658854f2a04a92b5be09`.
An independent finalized read matched the private journal's epoch ID
`0xef86093e44b5e9bb5c24070844f6f01bec431b662acf6c033db5028f5662b709`,
state/event/policy roots, publication event hash, and action sequence 5.
The source-matched `e51c6de9` manifest still matches all 66 verifier keys;
the ledger now reports governance action count 6 and one published epoch.
The journal and development signer remain private in the ignored smoke-state
directory. This epoch anchors only a development registry snapshot, **not**
the fixture issuer's authorization statement. It does not satisfy the governed
issuer decision reader, live VP status authority, or release qualification.
After a process restart or ambiguous response, reconcile the exact epoch ID
from the private one-shot journal rather than retrying publication:

```sh
node --env-file=artifacts/ledger9-current-chain.env \
  scripts/reconcile-ledger9-epoch.mjs \
  --journal artifacts/ledger9-current-chain-smoke-state/development-registry-epoch.json \
  --manifest artifacts/ledger9-current-chain-pack/release-manifest.json
```

The command checks the pinned chain, source-matched verifier-key catalog,
journal payload commitment, and selected finalized epoch roots. It exits 0
only for a finalized match, 2 for unresolved inclusion that must be inspected,
and 1 for invalid or conflicting evidence. Its `recordedTxId` is copied from
the private submission receipt, not independently proven by the ledger reader.
It never submits a transaction.

The pinned read-only Registry command now reports the selected issuer's
`lifecycleEventRoot` and whether the selected (or latest) epoch's `eventRoot`
matches it. This is only one necessary decision-reader condition, not a
qualification verdict: DID state, scope, inclusion, policy, and status must
still be independently authenticated. At indexed height 3601, the live
source-matched 66-key read reported `epochEventRootMatchesLifecycle: false`
for `issuer:local-development-fixture:v1`, as expected for the registry
snapshot epoch. A frozen offline install, installed identity-runtime gate,
full 66-circuit workspace typecheck, strict security-script typecheck, and
full-artifact inventory passed at local head `a660d816` before this read-only
diagnostic change. No new chain action or actor qualification occurred.

At signed local head `500ca537`, ten packages were packed from the full
Ledger 9 output and installed into an isolated consumer. The published VC
consumer fixture and packed signed issuer, verifier, auditor, maintainer, and
recognition journeys all passed. These are package-portability and fixture
results, not deployed actor evidence. The temporary tarballs were removed
after the smoke; the ignored source-matched deployment pack and private
journals remain preserved.

On the same pinned multi-user development chain, a distinct fixture verifier
proposal passed full-contract proof and wallet balance with broadcast blocked,
then was submitted once under a new private journal. Its proposal receipt was
`00c45430d88629100d16fdbb76aaee1c9e1ab701fb4cf74041d9aa9e8425d7c01e`.
Separate proof-only and journaled maintainer calls authorized and activated
that verifier, with receipts
`0042764fb10a7a06a95af3154dafc4e513bf3e65e4153dff7d6f5014e2e26f5337`
and `007491f1084b2cd9177d269c6744006ef3d10013fac79e15b4b11c02ebdab8fd8e`.
The repo-owned pinned read-only command at indexed height 3901 independently
found governance action count 9, one active verifier, all 66 verifier-key
hashes matching the source manifest, and the selected verifier's active
lifecycle at sequences 6/7/8. The existing snapshot epoch does **not** match
that verifier's lifecycle event root. These are development-only,
fixture-evidence-backed deployed transitions, not a live DID/VP-verified
application, accepted decision epoch, or release qualification. The one-shot
journals, receipts, proof logs, and fixture signer remain ignored and private;
do not replay the submissions. The shared node/indexer/proof-server lifecycle
was not changed.

The same pinned chain also accepted a separate fixture auditor lifecycle.
The proposal was proved with broadcast blocked, then submitted once under a
private journal (receipt
`008590c65207a5ad38e0ad40bbe236c30fb3aef89bc7ccef2d79e2d2e2231677ee`).
Separate proof-only passes preceded one-shot authorization and activation,
with receipts
`00aa0ab482660296ece70f4aca3a7d9e1ea8302478e897b1d998735d99d3794ed1`
and `00405ee95ef80f1cfdfb02c9e6fd0577203a105a6d6e7a0b616c970731cc819053`.
An independent read-only process at indexed height 4073 found governance
action count 12, one active auditor, and the selected auditor's proposed,
authorized, and active sequences 9/10/11. All 66 verifier-key hashes still
matched the source manifest. The selected auditor's lifecycle event root does
not match the earlier registry-snapshot epoch. This is deployed local
fixture-evidence governance testing, not a live DID/VP-verified auditor
application, accepted decision epoch, or release evidence. The private
journals and proof logs must not be replayed; the shared stack was not managed
or restarted.

An external-recognition fixture then exercised the deployed recognition
lifecycle on the same pinned development contract. Each step passed a
proof-only run with broadcast blocked before a separately journaled one-shot
submission. Proposal, authorization, and activation receipts were
`0004fba8cfbfb881d57b5b2c63a513a66667615a62ac2f725a55b20b13b56a7734`,
`005f5fb0f763cde5b906e59e3e1bc812c1476af9dbd487da8058fc37514808c35c`,
and `0003e797a3446d1aa6fffec8315cf99a4b6838cdb9b6040a35bf63ca291086df07`.
The pinned read-only command at indexed height 4224 independently reported
governance action count 15, one active recognition, lifecycle sequences
12/13/14, and all 66 verifier keys matching the source manifest. The earlier
snapshot epoch does not match this recognition's lifecycle event root. This
tests development-chain proof, submission, and finalized state for a fixture
external authority; it does not authenticate a real external registry,
qualify a live DID/VP journey, or provide release evidence. The ignored
one-shot journals and proof logs remain private and must not be replayed.

Before publishing an actor-specific decision epoch, the original fixture
issuer requires replacement rather than retroactive reinterpretation. Its
proposal committed the label `schema:local-development-fixture:v1` as the
resource ID, but the domain decision schema requires an ID produced by
`issuerGovernedResourceId` from an exact issuer scope. A valid canonical
candidate checked against the finalized record returned
`canonicalResourceIdCommitmentMatches: false` at indexed height 4276.
The fixture also committed `status:local-development-fixture:v1`, not a
`computeIssuerStatusPolicyBindingCommitment` result backed by a VC-owned
status authority. A new issuer proposal must bind the canonical scope ID,
governed status policy, authenticated DID session and accepted VP receipt
before its active lifecycle can be used for an actor-specific epoch and
decision bundle. The old fixture remains a useful contract-lifecycle smoke,
but cannot qualify that decision path.

A second development issuer fixture now uses the domain's canonical schema
resource ID and `computeIssuerStatusPolicyBindingCommitment` preimage. Its
proposal passed proof-only validation with broadcast blocked, then was
submitted once under a separate private journal (receipt
`008cc632915309e88484b2a73a49dd4f22743f794df89cc94ce2692c413aba56b3`).
The separately proved and journaled authorization and activation receipts
were `00335ebb04bb81addf7db6d4fc9567ffba063b4a0d95d7631a7654dae2ad7ca74c`
and `005688356581ab4426636bc9120e604915b36c92ed4e48ff02790ec2bb1fc5b16f`.
An independent pinned read at indexed height 4447 reported governance action
count 18, two active issuers, the new issuer's lifecycle sequences 15/16/17,
`canonicalResourceIdCommitmentMatches: true`, status-policy binding commitment
`0xc03e880d3053f086a96c5670f0b7eac9a67b40a943bff23db89473297fefa079`,
and all 66 verifier-key hashes matching the source manifest. The status
binding has a syntactically valid fixture preimage, not a verified VC-owned
live status authority. No accepted application VP receipt or authenticated
live DID session was submitted through the API, and no actor-specific epoch
was published. This is a stronger deployed canonical-shape smoke, still not
a qualified issuer decision or release evidence. Do not replay its one-shot
transactions or treat the shared-chain fixture signer as an operator key.

To repeat only the finalized readback on the current shared chain, use the
ignored local pin and source-matched manifest. The indexed height may advance
between runs; a different genesis, checkpoint, contract, or key catalog is a
stop condition:

```sh
node --env-file=artifacts/ledger9-current-chain.env scripts/read-ledger9-registry.mjs \
  --address 0xf80638c64dcf63138b222426549bedb122673391b414658854f2a04a92b5be09 \
  --issuer-label auth:issuer:ledger9-canonical-development:v1 \
  --issuer-resource-id tr:issuer-resource:v1:246716fb2652b22d1185766776827e8311b9c357bcf33dc3605d228e5e41d839 \
  --manifest artifacts/ledger9-current-chain-pack/release-manifest.json
```

The expected selected issuer is active with lifecycle sequences 15/16/17,
`canonicalResourceIdCommitmentMatches: true`, and
`epochEventRootMatchesLifecycle: false`. The last value is an explicit
qualification gap, not a transient indexer failure.

On 2026-11-17, a second, distinct fixture maintainer
(`participant:maintainer:ledger9-development-maintainer-2:v1`) passed a
full-contract proof with broadcast blocked, then its proposal was submitted
once to the pinned shared chain under a separate private journal. An
independent finalized-ledger read found governance action count 19 and the
candidate in `proposed` state; the proposal's finalized Compact event hash
`0x5956d1bb10932ea3e2ede29e28304e3533e43feb66be88aece0a97c5b74346b4`
matched the receipt. The journal was separately reconciled from that
finalized proposal record to `observed`. Authorization and activation each
passed a proof-only run with broadcast blocked before separate one-shot
submissions. Their finalized transaction receipts were
`0061cfe9dc7704b6dae4ec28431b71e027729e14b554497df2c2e2c5979f846422`
and `006cf1a3a4815a812150f771488d93cefeaca993dab223d32e985dd7d38be2a95d`.
A separate read-only process on the pinned chain found governance action count
21, two active maintainers, threshold one, the candidate's active membership,
and all 66 verifier-key hashes matching the source manifest. The private
one-shot journals and fixture runner are ignored; never replay these calls.
This fixture onboarding is not an accepted VP, independent operator approval,
or release evidence. The shared chain may advance from unrelated users without
invalidating this observation; a changed chain identity or contract is a stop
condition.

A third fixture candidate (`participant:maintainer:ledger9-development-maintainer-3:v1`)
then passed proof-only proposal, authorization, and activation before separate
one-shot submissions. The proposal's finalized event hash
`0x40e7f8fa29b3f065737811126b7f00ca76e918c802ca7603b78915fca8be6168`
matched its journal, which was reconciled to `observed`. Authorization and
activation receipts were
`0011bdffae19db5567594e8fa3667276afd684ddf4a12bb47171bc75ea38561dac`
and `0007e3fc3d8e0bef542a88ada25bb23518daaa21a9559775a4d748de780dc07330`.
An independent pinned-chain read reported governance action count 24, three
active maintainers with three distinct public keys and DID commitments, and
all 66 source-matched verifier keys. The threshold is still **one**. These
fixture identities and signatures do not represent independent operators or
accepted VP admission. The ignored private proposal and decision journals
must not be replayed.

The approved local-ledger API plan requires at least three distinct
maintainers and a threshold of at least two. The development contract now has
three distinct fixture maintainers, but remains at threshold one and cannot yet
qualify the live DID/VP API path. The integration package now provides
`prepareUnsignedLocalMaintainerProposalCall` to derive the first candidate's
deployment-bound signing context from an independently authenticated finalized
ledger. `prepareLocalMaintainerProposalCall` verifies the evidence-verifier
signature and current distinct maintainer signatures. The separate
`submitLocalMaintainerProposalCall` path requires a deployment-bound one-shot
journal and a guarded transport, and rechecks the reserved action before
broadcast. These helpers do not themselves verify an accepted application VP;
the caller must supply that admission evidence through the governed intake.
Read-only verification also confirms that its version-1 policy commitment is
the bootstrap's `bytes32Commitment("policy:local-development-smoke")`, not a
canonical `GovernancePolicySnapshot` commitment. Therefore, even a successful
threshold-update circuit on this contract would not retroactively establish a
canonical version-1 policy record or satisfy domain policy-revision continuity.
For future staged deployments, the new v2 plan pins the canonical policy
record's bytes and requires the approved provider to bootstrap its exact
derived snapshot commitment before any submission. The existing v1 plan and
deployed fixture remain unchanged. The development-only policy-bound provider
now has a separate source-matched pack, private plan, deployment journal, and
live readback, but its policy record is not independently reviewed or approved.
It is not a release-qualified registry.
Before using a contract for API qualification, establish an independently
reviewable initial policy snapshot and exact next snapshot, update and finalize
the threshold policy, then execute
the separately approved maintenance-authority transition. Recheck the full
verifier-key catalog and governance history after each step. Keep each attempt
in a separate one-shot journal with independent finalized readback. The
development-only decision runner is not a production guarded membership API.
Do not substitute fixture signatures for the future accepted VP or independent
plan approval.

On 2026-11-18, a separate development-only staged deployment was submitted to
the same pinned shared Ledger 9 chain at
`0x096394c984078c8c0ed0dc2393446b2b5752298cfd7c46ce832e007f11edad84`.
Its source-matched v3 install manifest is from `3aae2acd`, and its initial
governance policy commitment is derived from a canonical active v1 policy
record rather than the older fixture's opaque policy label. The policy record
is a development draft, not an independently approved release policy. An
independent finalized read at indexed height 6495 matched all 66 verifier-key
hashes and maintenance counter 65 against the manifest. The 65 post-deployment
key insertions each have a successful one-shot receipt. Two receiptless
transport attempts were independently reconciled as absent, remained absent
after more finalized blocks with no pending node extrinsics, and were archived
before explicit, successful development-only retries. The original reservations
and recovery records are retained in private local evidence; neither retry is
an automatic or release-qualified recovery procedure.

The next development-only action registered one fixture evidence-verifier key
on that policy-bound contract. A full proof reached a deliberately blocked
broadcast guard before a separate one-shot submission. Independent finalized
readback at indexed height 6637 reported governance action count 2, one active
evidence-verifier key, and all 66 verifier-key hashes still matching source
`3aae2acd`. This is deployed Ledger 9 proof, submission, and readback for a
fixture governance action. It does not establish accepted DID/VP evidence,
threshold-two policy, approved maintenance transition, a qualified epoch, or
release readiness. Two more fixture maintainers were subsequently proposed,
authorized, and activated through separate proof-only and one-shot submission
journals. An independent finalized read at indexed height 6977 reported
governance action count 8, three active maintainers with distinct DID
commitments and JubJub public keys, one evidence-verifier key, and all 66
verifier-key hashes still matching the source-matched manifest. A canonical v2
development policy record was derived from the pinned v1 record and validated
as the exact next snapshot. Its full threshold-revision proof reached a blocked
broadcast guard; a separate one-shot journal then submitted the transaction.
Independent finalized readback at indexed height 7047 reported governance
action count 9, three active maintainers, a **two-of-three** default, emergency,
and archival threshold, and all 66 verifier-key hashes still matching the
manifest. The v2 policy commitment is
`0xf32837e9b989905892312f6dc0a6ee915c1ba4f1125aa8b8220913e15e93d166`.
These fixture identities are not independent operators. The policy records
are development drafts, not independently approved release policy. These
actions do not demonstrate accepted DID/VP evidence, an approved
maintenance-authority transition, a published epoch, or release readiness.
The older fixture contract and its journals remain separate and must not be
replayed.

A v2 fixture evidence-verifier key was then registered with two distinct
active maintainer signatures. Its full proof passed a blocked-broadcast guard,
and an independent finalized read confirmed the exact v2 key record, governance
action count 10, and all 66 source-matched verifier keys. A schema-scoped issuer
proposal using this key and two maintainer signatures also passed proof-only
validation. Its first journaled submission was blocked locally before the
provider transport by a misconfigured private broadcast guard. That journal
was preserved. After finalized absence and an empty node pending pool were
verified, one explicit development-only retry used a separate journal and
reached the node, which rejected it with `Invalid Transaction: Custom error:
138`. [Midnight's node error list](https://docs.midnight.network/nodes/error-codes)
names 138 `BalanceCheckOverspend`: a negative balance in a transaction
segment. This may involve fee balancing, but the exact failing segment is not
yet established. The retry journal remains reserved with no submitted receipt;
the finalized registry remains at action count 10 with zero issuers and no
pending node extrinsics. Do not replay either journal or claim an issuer
journey succeeded. Diagnose the transaction balance and reconcile the failed
attempt before any new issuer submission. Even a successful fixture issuer
proposal would not establish accepted VP admission.
Issue [#323](https://github.com/midnightntwrk/midnight-trust-registry/issues/323)
tracks the balance rejection and journal reconciliation under
`milestone-0.2.0`. Two subsequent proof-only runs on the same pinned chain
decoded the SDK-balanced Ledger 9 transaction before a deliberately blocked
submission. Both contained two intent segments, one DUST spend with declared
`vFee` `128168039079190`, and no imbalances reported by the ledger API when
given the computed transaction fee (respectively `839600000000001` and
`840600000000001`). These fresh balanced transactions were **not** submitted
and do not prove the rejected transaction had the same inputs or that the
node's error was transient. They only narrow the investigation: the prior
error 138 is not explained by a basic imbalance in either fresh transaction.
The private diagnostic receipts are retained locally; no new proposal journal
was created. A later independent finalized read still found governance action
count 10, zero active issuers, three active maintainers, threshold two, and 66
source-matched verifier keys. Keep both original reservations untouched until
the exact failed transport transaction and its chain-state inputs are
reconciled. Do not automatically retry a shared public-seed wallet transaction.
The owner-managed node advertises `system_dryRun` but rejects external calls
with `RPC call is unsafe to be called externally`. A proof-only attempt to
query it stopped without a diagnostic receipt or broadcast; do not change the
shared node configuration merely for this test. A separate development issuer
wallet was prepared locally with a private ignored seed, its own public
address, and a pinned genesis/checkpoint receipt. A bounded funding transfer
finalized as transaction
`008e0249167215060eee5a5a80973ab8c1ec93932c7f142478e80cd9f7da5a38de`;
independent recipient sync found `1000000000000` smallest NIGHT units on the
pinned chain. The first funding attempt failed before transaction construction
and is retained with its pre-broadcast recovery receipt. The successful
transfer used a separate one-shot journal. A subsequent read-only sync found
zero spendable DUST and one unregistered NIGHT output. The first registration
attempt stopped during local generic validation, which reported zero DUST
available for the still-unregistered output; no transaction bytes or submission
receipt were written. That reservation and its pre-broadcast recovery receipt
are retained. A separate guarded registration, following the SDK's own
first-registration fee-coverage path, finalized as transaction
`00373629ccb19683e509470b9943e7c3d933026f5300cdcb35ec56451343288580`.
Independent recipient sync then found no unregistered NIGHT outputs and
`6357034060231668571` spendable DUST units. The dedicated wallet has not
submitted a registry action at that point. The old proposal reservations remain untouched.
A fresh issuer proposal with the dedicated wallet passed full proof with its
broadcast provider blocked. One separate journaled submission then reached
the node and was rejected with the same `Invalid Transaction: Custom error:
138` as the earlier public-wallet attempt. The dedicated proposal journal is
reserved with no `.submitted` receipt. Independent finalized readback found
governance action count 10, zero issuers, and all 66 source-matched verifier
keys; the node's pending extrinsics list was empty. The rejection therefore
persisted across a funded, DUST-registered, distinct wallet. None of the three
old proposal journals was retried.

The [official Ledger 9 compatibility matrix](https://docs.midnight.network/relnotes/support-matrix)
then identified the 17 November client patch: Midnight.js/testkit 5.0.1,
Compact.js 3.0.2, Wallet SDK 2.0.1, on-chain runtime 4.0.2, and client ledger-v9
1.0.2. The [upgrade notes](https://docs.midnight.network/relnotes/ledger-9)
document a `BalanceCheckOverspend` fee mismatch between node 2.1.101 and
ledger-v9 1.0.0 for a state-deleting maintenance call; that is evidence for
upgrading but not proof that the issuer proposal had exactly the same cause.
The exact-version lockfile was updated and installed without rebuilding the
deployed Compact artifacts. The identity runtime guard, prebuilt typecheck,
249 local-ledger preflight tests, and 398 integration tests passed.
The published DID Jubjub RC1 package still declares an exact transitive
`@midnightntwrk/ledger-v9@1.0.0`, so the installed graph contains both that
version and the Registry client's `1.0.2`. Its published JavaScript does not
import the ledger transaction API; it uses Compact runtime and hash utilities
for signing. This narrows the observed fee-compatibility concern to transaction
construction, but does not prove the whole DID/VP actor path compatible. Do
not override the published package's exact dependency without a separate DID
qualification.

With the patched client cohort and the same dedicated wallet, a new
proof-only issuer call passed behind a blocked broadcast provider. A separate
one-shot journaled submission then finalized. An independent read at indexed
height 12504 found governance action count 11 and the issuer record in
`proposed` status at sequence 10; its lifecycle event root matched the
submission receipt, and all 66 verifier keys still matched the source-pinned
manifest. The patched journal is `submitted`. This demonstrates a deployed
fixture issuer proposal, not an accepted DID/VP admission, authorization,
activation, epoch publication, or release qualification. The three older
reserved proposal journals and their private evidence remain intact pending
explicit reconciliation. The public smoke wallet is not an isolation boundary
on a multi-user shared chain.

At local signed head `4693c7e5`, ten Registry tarballs were packed into an
exclusive temporary target and installed into a fresh consumer. The packed
Ledger 9 VC fixture and signed issuer, verifier, auditor, maintainer, and
recognition fixture journeys passed with the patched dependency graph. The
temporary target was removed after the test; the source-matched deployment
bundle and private journals were retained. This is package portability and
fixture evidence, not a finalized DID/VP actor journey.

On the pinned shared chain, a two-maintainer fixture authorization proved
behind a blocked broadcast provider and then finalized as transaction
`00f66228d0909ab94ae84247e69719fe20b8b9ab6506b43e9429fe1616ff8e0d0a`.
Independent readback found the issuer `authorized` at governance sequence 12
and matched event root
`0xe00d7b3a07299cef627fa907e46e67cb8c1585d2eeb00907f0ef5d58a9ff7173`.
A separate proof-only activation and one-shot submission finalized as
`008efc51058b33c1f679e19e703988279b8fee706a002d97253c26b1747a4545bc`.
Independent readback at indexed height 12794 found the issuer `active`, active
issuer count one, governance sequence 13, and lifecycle event root
`0xb3df7f19ba5a64c97aa6c4035ff9488bbdc858d2c8ed90f2ca01b61ba5d19a6b`;
all 66 verifier keys still matched the source-pinned manifest. The private
proof, reservation, and submission receipts are preserved. These actions used
explicitly labeled fixture evidence, not an accepted VP, and no epoch was
published. A real DID/VP admission and a defensible authorization statement
and inclusion root are prerequisites for claiming a deployed actor E2E result.

## Execution order

On 2026-11-18, the non-destructive `pnpm run integration:prebuilt` lane passed
at signed/DCO code head `9655de46`: 66 full proof circuits were present before
and after the run; installed VC Compact composition passed; integration, API,
applicant-portal, and admin-console suites passed 405, 113, 72, and 31 tests
respectively. The governed, auditor, membership, and signed demo journeys also
completed. These are simulator and file-backed regression results, not shared-
chain DID/VP admission or finalized actor E2E. At the same code head, a pinned
read-only attach confirmed that the indexer's current block was at the node-
reported finalized height and hash. This confirms consistency with the
attached node, not independent finality or a release approval.

On 2026-11-18, the current local branch passed the installed identity/runtime
gate (22 tests; six DID identity packages on runtime 0.21.0), the full-artifact
inventory check (66 proof circuits), and the published-VP intake cone (6 tests).
The read-only, genesis/checkpoint-pinned shared-chain query at indexed height
13549 found 66 verifier keys matching the source manifest, two active issuers,
one published epoch, and an active fixture issuer whose lifecycle event root
still differs from that epoch's event root. None of these checks is a deployed
DID/VP actor journey. Signed local commits `e0a104bb` and `73046372` add a
private-witness status refresh that rechecks the accepted evidence signature
and rejects a private admission snapshot differing from the proposal's public
snapshot. The host still needs a live VC-owned status authority, authenticated
DID/VP and finalized-state adapters, approved writer inputs, and an actual
one-shot actor submission before #322 can pass. No shared-chain transaction or
container lifecycle action was performed for this check.

The three older policy-bound issuer reservations and the later successful
patched-client attempt share the same authorization ID, evidence commitment,
and action context. A finalized proposal cannot identify which journal attempt
landed from those fields. The local journal now refuses to mark a reservation
with no recorded event hash `observed` merely because such a proposal appears;
the original files remain quarantined. A regression covers this exact
cross-journal attribution case. This is a fail-closed guard, not disposition
of the old reservations: #323 still needs independently attributable
transaction evidence or an approved recovery path.

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
6. Run fixture CI, then qualify deployed actor journeys on the owner's shared
   multi-user Ledger 9 chain. Pin genesis and a non-genesis checkpoint, use a
   dedicated wallet and one-shot journal per attempt, and tolerate unrelated
   head advancement while rejecting chain, contract, or source-image drift.
   Cover DID session, VP evidence, issuer/verifier/auditor submissions,
   maintainer votes, and finalized readback. Tests that require a chain restart,
   restore, or deliberately ambiguous submission must use an explicitly isolated
   project; never disrupt the shared stack. Record the exact source, image,
   genesis, checkpoint, and contract identities. Browser/CLI fixture tests and
   the deployed fixture transitions above are not live DID/VP qualification.

The work is tracked under [#292](https://github.com/midnightntwrk/midnight-trust-registry/issues/292):
[#319](https://github.com/midnightntwrk/midnight-trust-registry/issues/319)
infrastructure, [#320](https://github.com/midnightntwrk/midnight-trust-registry/issues/320)
SDK/DID/VC, [#321](https://github.com/midnightntwrk/midnight-trust-registry/issues/321)
Compact artifacts, and [#322](https://github.com/midnightntwrk/midnight-trust-registry/issues/322)
end-to-end qualification.
