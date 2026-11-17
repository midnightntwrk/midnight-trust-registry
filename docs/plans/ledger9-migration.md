# Ledger 9 migration plan

Status: local migration in progress. This document is not a deployed or release
qualification claim. The historical Ledger 8 source is the `ledger8` branch at
`5abc1575922d3f0cc7234f5f1d4c0a77e045fcfd`.

## Selected official matrix

| Component | Selected version | Current migration state |
| --- | --- | --- |
| Node | 2.1.101 | Pinned local container healthy; `system_version` returns `2.1.101-86774edf`, runtime `specVersion` is `2001100` |
| Ledger | 9.1.0.1 | Official image cohort and protocol-version evidence; no independent crate-version attestation from RPC |
| Indexer standalone | 4.4.101 | Pinned local container healthy; GraphQL serves indexed blocks and the matching genesis |
| Proof server | 9.0.0 | Pinned local container listening on loopback with read-only parameter cache and fetching disabled; no TR proof run |
| Compact compiler | 0.36.0 | Pinned Nix toolchain builds; contract compiles with `--skip-zk` after source type fixes |
| Compact runtime | 0.21.0 | Locally installed with exact DID RC1 and VC PR #755 artifacts; simulator/integration tests pass, deployed runtime unqualified |
| Midnight.js / testkit-js | 5.0.0 | Locally installed; simulator/integration tests pass, deployed provider journey unqualified |
| Compact.js | 3.0.0 | Locally installed; simulator, client, harness, and integration tests use awaited circuit/read APIs |
| `@midnightntwrk/ledger-v9` | 1.0.0 | Required for new Ledger 9 transactions |
| `@midnightntwrk/onchain-runtime-v4` | 4.0.0 | Required where directly consumed |
| Midnight DID | exact 1.0.0-rc1 cohort | Published and installed locally under four dated, exact-version age exceptions |
| VC Compact and DID binding | PR #755 source, 0.4.0 artifacts | Built from exact PR head locally; not merged or published to npm |

The installed-identity guard now accepts those local `file:` tarballs only when
their bytes match the SHA-512 integrity in the frozen pnpm lockfile and their
paths remain inside this checkout. Its 23 unit tests and installed-package
check pass for six identity packages at Compact runtime 0.21.0. This is a local
trial, not a portable dependency or a substitute for publishing VC 0.4.0.
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

The local VC trial source is [PR #755](https://github.com/midnightntwrk/midnight-verifiable-credentials/pull/755)
at `dad8b2cae38c9971adb43d124ead1281b021416b`. Its Nix `npm-artifacts`
target built three tarballs. This worktree has private, ignored copies under
`artifacts/ledger9-vc-pr755/`; the temporary `file:` overrides intentionally
make frozen installs depend on those exact local inputs. They must be replaced
with published `0.4.0` pins and a regenerated lockfile before a portable PR.

| Trial tarball | SHA-256 |
| --- | --- |
| `midnight-ntwrk-credential-compact-0.4.0.tgz` | `10ded7cf431103f0031873e5b489eb5dc1853365694e1cbf2d15b384c8f563c7` |
| `midnight-ntwrk-credential-did-midnight-0.4.0.tgz` | `4fa92d305a152e8d1239c0997fa86bcfd189eb952e08763a82dcaf407b143400` |
| `midnight-ntwrk-credential-model-0.4.0.tgz` | `cc12db936817281e9c41b64c70b45131f6610c6634a7353bd9ad398f20610866` |

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

With these services running, `pnpm check:ledger9-local-stack` repeats the
loopback-only node version, runtime protocol, node/indexer genesis, indexed
block protocol, and proof-server reachability checks. Set
`TR_EXPECTED_GENESIS_HASH` to an independently approved value if the check must
also enforce a particular local chain; ports can be overridden with
`TR_NODE_PORT`, `TR_INDEXER_PORT`, and `TR_PROOF_PORT`. The command does not sign
or approve genesis, exercise a proof, deploy a contract, or establish
transaction finality. It is intentionally not part of offline CI.
The most recent live recheck after the API migration timed out: the local
node's loopback RPC returned no bytes within five seconds, and Docker CLI
queries did not complete. The three stack-check unit tests still pass, but
the live stack is not currently verified healthy. Do not infer a source
regression from this timeout or claim deployed qualification; inspect Docker
Desktop and the dedicated project containers before the next runtime phase.
Offline source validation at `e7e02633` now passes the repository lint gate,
127 standalone-topology cases, 244 local-ledger preflight cases, and strict
security-script typecheck. The standalone install policy is tested against
the checked-in Ledger 9 Compose project name. The Ledger 9 development stack
has a project-private host-access bridge for loopback forwarding; the stricter
offline topology observer still rejects that extra attachment, rather than
misreporting it as an internal-only runtime. These source checks do not prove
the currently unresponsive live stack or a deployed actor journey.
The separate `test:demo-smoke-scripts` gate is still red. Its historical
adversarial/demo cases call asynchronous Ledger 9 harness and simulator
operations as if they were synchronous, producing failed assertions and
unhandled rejections. All 40 `scripts/adversarial-compact.test.mjs` cases now
pass after awaiting setup, circuit results, client verification, and expected
rejections. The five isolated maintainer-safety demo tests also pass. Other
adversarial API, application-evidence, and governed-demo cases still require
async migration and a complete gate rerun; no failed case has been skipped or
reclassified as a pass.

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
