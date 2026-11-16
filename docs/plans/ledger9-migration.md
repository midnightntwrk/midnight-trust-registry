# Ledger 9 migration plan

Status: local migration in progress. This document is not a deployed or release
qualification claim. The historical Ledger 8 source is the `ledger8` branch at
`5abc1575922d3f0cc7234f5f1d4c0a77e045fcfd`.

## Selected official matrix

| Component | Selected version | Current migration state |
| --- | --- | --- |
| Node | 2.1.101 | Default Compose image pinned by digest; render checked |
| Ledger | 9.1.0.1 | Expected node runtime; live RPC not yet checked |
| Indexer standalone | 4.4.101 | Default Compose image pinned by digest; render checked |
| Proof server | 9.0.0 | Default Compose image pinned by digest; render checked |
| Compact compiler | 0.36.0 | Pinned Nix toolchain builds; contract compiles with `--skip-zk` after source type fixes |
| Compact runtime | 0.21.0 | Locally installed with exact DID RC1 and VC PR #755 artifacts; runtime validation incomplete |
| Midnight.js / testkit-js | 5.0.0 | Locally installed; provider and async circuit API migration incomplete |
| Compact.js | 3.0.0 | Locally installed; simulator still assumes synchronous circuits |
| `@midnightntwrk/ledger-v9` | 1.0.0 | Required for new Ledger 9 transactions |
| `@midnightntwrk/onchain-runtime-v4` | 4.0.0 | Required where directly consumed |
| Midnight DID | exact 1.0.0-rc1 cohort | Published and installed locally under four dated, exact-version age exceptions |
| VC Compact and DID binding | PR #755 source, 0.4.0 artifacts | Built from exact PR head locally; not merged or published to npm |

The official [Ledger 9 upgrade guide](https://docs.midnight.network/relnotes/ledger-9)
is the compatibility source. The
[Midnight.js 5 notes](https://docs.midnight.network/relnotes/midnight-js/midnight-js-5-0-0)
cover ESM, provider `config`, era-aware types and removal of `setNetworkId()`.
The [indexer 4.4.101 notes](https://docs.midnight.network/relnotes/midnight-indexer/midnight-indexer-4-4-101)
require a new index for older 4.3 data. Exact Docker image digests are in
`deploy/standalone/compose.yml`; `node scripts/check-standalone-compose-render.mjs`
validates the base and offline configurations without starting containers.

The registry contract and trust-state model do not require VC. VP-based
application evidence does. The current API also imports the VC package's
`resolveMidnightDIDMethodBinding` for actor authentication and mutation
intents; that is a removable implementation coupling, not a registry
protocol requirement. Core DID authentication should use DID-owned resolution
before the VC release gate is applied only to VP evidence journeys.

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

Current compile evidence is limited to `compact:light`. Contract TypeScript
typecheck is red because generated `initialState` and impure circuits are
asynchronous and the simulator still uses synchronous `CircuitResults`; this
is a source migration, not a missing package or a qualification pass. No new
proving/verifier keys or deployed transactions have been generated.

## Execution order

1. Keep the `ledger8` source branch only as a historical reference. Ledger 9
   replaces the default standalone Compose stack; there is no parallel Ledger 8
   runtime profile. Remove old node/indexer volumes only after confirming they
   belong to this project and no active container uses them. Never reuse an
   older database with indexer 4.4.101.
2. Qualify the three official images in the default Compose file. Confirm `system_version` starts
   with `2.1.101`, `state_getRuntimeVersion.specVersion` is `2001100`, and
   `midnight_ledgerVersion` names `crate-ledger-9.1.0.1`. Confirm indexer
   genesis, progress and contract-state decoding before application calls.
3. Consume published, exact-version DID 1.0.0-rc1 packages. Decouple the API's
   DID method lookup from the VC-owned binding helper without weakening key
   relationship, controller or origin checks. Core actor authentication can
   qualify before the VC migration. VP evidence journeys wait for a tested
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
