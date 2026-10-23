# Standalone Offline Runtime Qualification

Status: **0.1.0 release-candidate gate**, not a claim that the full stack is deployed or
supported offline. Online access is allowed during installation; after setup,
the running Trust Registry must not depend on public network services.

Preprod qualification is deferred to a later public-network release. A local Compact simulator
and loopback HTTP actor journey are useful development evidence, but are not a
deployed standalone Midnight ledger or a substitute for public-network
finality. Offline operation also does not make a local node or status authority
trustworthy by itself.

## Install While Online

1. Pin a reviewed version of the maintained
   [midnight-examples](https://github.com/midnightntwrk/midnight-examples)
   local-network tooling and its node, indexer, and proof-server image digests.
   The older `midnight-local-dev` repository is archived; do not install an
   unreviewed floating version from it. Install Node.js,
   pnpm dependencies, Docker Compose, and the signed Trust Registry packages
   while online. Record the exact versions, image digests, manifest hash, and
   software bill of materials. Do not rely on floating image tags at restart.
2. Build the full Compact contract and preserve its generated artifacts and
   release manifest. Stage any required local DID, VC, and status-authority
   components and trust anchors before disconnecting. No runtime component
   may resolve packages, fetch a public DID document, or query an external
   status service after the installation boundary.
3. Provision distinct local wallet, proof-server, node, indexer, API, admin
   console, and applicant-portal identities. Keep wallet seeds, maintenance
   keys, API credentials, and proof inputs out of images, fixtures, and logs.

The API has a separate candidate OCI builder:

```sh
node scripts/build-api-runtime-image.mjs <digest-pinned-node-base> <linux/arm64|linux/amd64> <external-new-output-directory> <signed-source-SHA> <approved-source-signing-fingerprint>
```

It exports the signed source commit, performs a frozen light build, deploys
production-only dependencies from the shared lockfile without lifecycle
scripts or optional native addons, removes the known published DID 0.7.0 proof payload from its isolated
staging copy, and scans the complete payload for remaining proving artifacts.
Volatile pnpm install metadata is omitted from the runtime. The manifest
records the lockfile, Dockerfile, payload and archive hashes; repeat builds
may have different OCI archive hashes even when the runtime payload matches.
The digest-pinned base must include `/usr/bin/gpg`;
the builder checks GPG and the API import in a read-only, network-disabled
container before exporting. Build it while online. This is packaging evidence,
not a running local-ledger qualification. The v4/v5 installer pins its archive;
the first-run operator must later verify the running
image digest, review the API plan, and verify offline operation.
Local-ledger API mode currently binds to loopback only, so Docker port
publishing does not expose it; a reviewed sidecar/shared-network-namespace
topology is needed before cluster use. Plan verification also needs a writable
`/tmp` and a GPG keyring owned by the runtime uid (1000) with mode `0700`.

The staged install directory must contain `install-inventory.json`, the
release-candidate package manifest and its ten tarballs, separate OCI image
archives for node, indexer, and proof server, and the proof server's verified
Ledger 8 public-parameter cache. Use this shape, replacing every
placeholder with approved exact values:

```json
{
  "format": "tr-standalone-install-v3",
  "sourceRevision": "<40-character signed source SHA>",
  "packageManifest": "release-manifest.json",
  "artifactDirectory": "packages",
  "runtimeCompose": {
    "path": "compose.yml",
    "sha256": "<sha256>",
    "offlinePath": "compose.offline.yml",
    "offlineSha256": "<sha256>"
  },
  "images": [
    { "role": "node", "reference": "registry.example/node@sha256:<digest>", "archive": "images/node.tar", "archiveSha256": "<archive sha256>" },
    { "role": "indexer", "reference": "registry.example/indexer@sha256:<digest>", "archive": "images/indexer.tar", "archiveSha256": "<archive sha256>" },
    { "role": "proof-server", "reference": "registry.example/proof-server@sha256:<digest>", "archive": "images/proof-server.tar", "archiveSha256": "<archive sha256>" }
  ],
  "proofParameters": {
    "directory": "proof-params",
    "files": [
      { "path": "bls_midnight_2p10", "sha256": "<sha256>" },
      { "path": "bls_midnight_2p11", "sha256": "<sha256>" },
      { "path": "bls_midnight_2p12", "sha256": "<sha256>" },
      { "path": "bls_midnight_2p13", "sha256": "<sha256>" },
      { "path": "bls_midnight_2p14", "sha256": "<sha256>" },
      { "path": "bls_midnight_2p15", "sha256": "<sha256>" },
      { "path": "dust/9/spend.prover", "sha256": "<sha256>" },
      { "path": "dust/9/spend.verifier", "sha256": "<sha256>" },
      { "path": "dust/9/spend.bzkir", "sha256": "<sha256>" },
      { "path": "zswap/9/spend.prover", "sha256": "<sha256>" },
      { "path": "zswap/9/spend.verifier", "sha256": "<sha256>" },
      { "path": "zswap/9/spend.bzkir", "sha256": "<sha256>" },
      { "path": "zswap/9/output.prover", "sha256": "<sha256>" },
      { "path": "zswap/9/output.verifier", "sha256": "<sha256>" },
      { "path": "zswap/9/output.bzkir", "sha256": "<sha256>" },
      { "path": "zswap/9/sign.prover", "sha256": "<sha256>" },
      { "path": "zswap/9/sign.verifier", "sha256": "<sha256>" },
      { "path": "zswap/9/sign.bzkir", "sha256": "<sha256>" }
    ]
  }
}
```

From a clean, GPG-signed and DCO-signed source commit with full generated
contract artifacts already present, run `pnpm run artifacts:standalone-install`.
To include a separately built API image from the **same signed source SHA**,
run instead:

```sh
node scripts/build-standalone-install.mjs --api-image-dir <absolute-api-image-output-directory>
```

This writes a v4 inventory with
`images/api.manifest.json` and `images/api.image.tar` pinned by exact hashes.
To include both static portals in the same signed-source install candidate,
first build each with `scripts/build-static-runtime-image.mjs` from the same
source SHA, then run:

```sh
node scripts/build-standalone-install.mjs --api-image-dir <absolute-api-image-output-directory> --admin-image-dir <absolute-admin-image-output-directory> --applicant-image-dir <absolute-applicant-image-output-directory>
```

The all-or-nothing portal options write a v6 inventory with six image
archives. Bundle verification checks each portal's OCI index, runtime role,
source revision, asset-list checksum, and archive hash, and pins the temporary
installation relay script by path and SHA-256. The offline loader imports
source-scoped admin and applicant tags without a registry pull. A v5/v6 Helm
mapping reads these portal identities from the verified bundle rather than
separate portal manifests. This is install-byte evidence only: neither the
loader nor the wizard starts the portals or establishes an offline actor
journey. The approved installer plan must still bind the six running image
identities and qualify the deployed API and portals with egress denied.

After loading the v5/v6 images, run
`node scripts/check-standalone-static-assets.mjs <verified-v5-or-v6-bundle>` on the
same Docker host. It creates disposable, network-disabled containers without
starting them, reads a bounded tar stream from each portal image's
`/app/public` tree and the API image's `/app/portals` tree without extracting
onto the host filesystem, and compares every regular file, size, and hash
against the verified portal manifests. It rejects extra files, directories
not implied by the manifests, links, case-colliding paths, unsupported tar
headers, and image-declared volumes. File modes and ownership are not compared.
The readback accepts
the verified OCI index ID or config ID from the local Docker image store.
Retain the reported image IDs and inventory hash as
install readback evidence. This check requires locally loaded exact images;
it is not an offline browser journey, a process-level egress test, proof of
image build provenance, or qualification of a newer source revision.

The verifier checks that the API archive's OCI image ID, Linux architecture,
non-root entrypoint, and source-revision label match the builder manifest and
the package release revision. The offline loader then imports a source-scoped
`tr-standalone/api` tag without pulling. It rejects image-name annotations,
unapproved platform variants, and selected Node execution-injection settings.
For this arm64 local RC, build and export with Docker's containerd image store
and the default attestation index enabled; classic-store or direct-manifest
API archives are not yet supported. The ledger image checker permits only a
distribution-source annotation matching the pinned repository, never an image
name or tag annotation. The loader snapshots one checked archive at a time to
a private temporary directory, rehashes it before Docker reads it, and
accepts the checked OCI or config ID reported by the daemon. Ensure the
temporary filesystem can hold the largest image archive. A v3 bundle remains a ledger-stack
bundle only; neither format starts the API or proves that it can query a live
local ledger. Matching source labels and hashes do not independently prove
image build provenance; the release operator must approve the exact archive
digest and retain the signed build evidence.

For an isolated cluster, the API may listen on `0.0.0.0` only with
`--cluster-bind`, a complete detached-reviewer-signed local-ledger plan, and a
signed v4, v5, or v6 install inventory with an API archive pin. Before opening that
listener, it checks a file at `/app/source-revision` in the container
filesystem against the approved plan. The listener bounds header, request,
idle-socket, and keep-alive waits and has a 16-connection cap; it does not
emit wildcard CORS headers. These limits do not cancel a stalled indexer
provider call, which remains a runtime resilience and qualification gate. Snapshot and
workspace modes and unsafe demo mutations cannot use this option. The operator
must still keep the API on a private service, use a read-only image filesystem,
allow only authorized in-cluster callers through network policy, and separately
qualify ingress/TLS and finalized ledger reads. The file check is a consistency
guard, not image provenance or proof that the cluster denies egress. No chart
or cluster qualification is implied by this CLI option.

The builder creates a **new** ignored `artifacts/standalone-install/<source SHA>/`
directory; it does not overwrite an existing bundle or rebuild Compact keys.
The full-artifact preflight requires the packaged Compact source bytes to match
the current source. That comparison catches a stale source copy but does not
prove that the compiler outputs or proving keys came from those bytes;
independently review the build provenance before release approval.
It packs ten packages, copies the 18 local proof-parameter files, exports the
three digest-pinned Compose images, copies and hashes both runtime Compose
files, writes the release and install manifests,
and runs the read-only bundle verifier. Retain the resulting directory and
hashes as candidate bytes for operator approval. If the command fails, the
partial directory is retained for inspection; use a new signed source commit
or a separately reviewed recovery procedure rather than silently replacing
candidate bytes.

Run `node scripts/check-standalone-install.mjs <bundle-directory>` before
disconnecting and after transfer. It verifies the package manifest against
the packed contract, including the manifest's Compact-source and generated
contract hashes against the corresponding tarball bytes, and hashes each
image archive and all 18 required proof
parameter files without network access. A missing, extra, linked, or altered
parameter file fails the check. The proof server verifies downloaded parameter
contents during online installation; keep the checked cache as a read-only
runtime input, not as an unpinned writable container layer.
The v3 verifier also checks both Compose files and requires the base Compose
image references to match the archived image inventory. V2 bundles remain
verifiable as historical smoke artifacts but cannot prepare a new wizard stack.
The verifier also checks each tagless OCI archive's internal manifest digest
against the approved image reference and its arm64 config bytes. It does not
establish who approved the reference or prove origin from the registry;
record independent registry-digest verification at acquisition.

On a clean offline host, run
`node scripts/load-standalone-install-images.mjs <verified-bundle-directory>`.
It rechecks the bundle, snapshots and hashes each archive in a private
temporary directory, loads those snapshots without pulling, verifies each Docker
image ID against the archived config bytes, and creates source-SHA-scoped
local tags. Reject a tag already bound to different bytes. Set
`TR_NODE_IMAGE`, `TR_INDEXER_IMAGE`, and `TR_PROOF_SERVER_IMAGE` to the returned
tags. Then use **both verified bundle copies**, not mutable checkout files,
with `docker compose -f <verified-bundle>/compose.yml -f
<verified-bundle>/compose.offline.yml up --pull never -d --wait`; the overlay
sets `pull_policy: never` for every image. Do this
on a separate clean host or daemon and capture load output, image IDs, restart
logs, and denied-egress evidence. A load against this development host, where
the upstream images are already present, does **not** prove clean offline
installation. Include pinned runtime,
browser, DID/VC/status, Compose, and toolchain dependencies in the operator
install record; this three-image inventory alone is not a complete install or
qualification result.

With the selected `TR_STACK_NAME` and loopback ports exported, run
`node scripts/check-standalone-topology.mjs <verified-bundle-directory>`
against the running ledger bridge. Bundle-aware observation matches each
container's image ID to the checked archive and requires Docker Compose's
recorded config-file paths to point into that bundle. Source-scoped local tags
are accepted only when all three services use the verified two-file offline
overlay. Running the check without a bundle is a historical digest-reference
smoke check, not pinned-install evidence. Neither form proves a clean-host
install, packet-level egress denial, actor journeys, or release qualification.

## Offline Runtime Boundary

The repository includes `deploy/standalone/compose.yml` as an **isolated
development smoke stack**, derived from a pinned `midnight-examples` revision.
It uses arm64 image digests, separate `tr-standalone-local-smoke` volumes, an
internal container network, and a read-only proof-parameter bind mount.
Provision `TR_INDEXER_PASSWORD`, a 64-character hex `TR_INDEXER_SECRET`, and
an absolute `TR_PROOF_PARAMS_DIR` pointing to the checked cache in a private,
untracked environment file before running
`docker compose --env-file <private-env-file> -f deploy/standalone/compose.yml
up -d --wait`. Never run `down -v` against a ledger whose history is evidence.
During online installation only, the dedicated proof-server container may be
temporarily attached to an egress-capable network to fetch and verify its
public parameters. Copy `/.cache/midnight/zk-params` to the checked install
bundle, then disconnect that network and recreate the proof container with
`TR_PROOF_PARAMS_DIR` mounted. The runtime Compose configuration disables
parameter fetching. A cold start alone does not prove cache completeness;
verify the exact 18-file inventory before running a real proof.
The image digests identify upstream bytes, not an approved distribution
channel. This Compose file does not start the Trust Registry API, portals,
wallet, DID/VC/status authority, or egress-denial harness and does not close
any release gate by itself. The node chain belongs under `/node/chain`; the
indexer SQLite state belongs under `/data`. Validate both named volumes across
restarts before using them for restore evidence.

To prepare an independent qualification instance without resetting an
ambiguous smoke ledger, choose a new `tr-standalone-local-*` project and three
distinct unused loopback ports. Compose's `-p` option isolates the node and
indexer volumes; do not copy or reuse the old setup directory, wallet state,
genesis approval, or deployment journal. For example, with a new private env
file containing the required secrets and pinned proof-parameter path:

```sh
export TR_STACK_NAME=tr-standalone-local-qualification
export COMPOSE_PROJECT_NAME="$TR_STACK_NAME"
export TR_NODE_PORT=39944 TR_INDEXER_PORT=38088 TR_PROOF_PORT=36300
docker compose --env-file <new-private-env-file> -p "$TR_STACK_NAME" \
  -f deploy/standalone/compose.yml config -q
# Start only after reviewing the project name, ports, and distinct volume names:
docker compose --env-file <new-private-env-file> -p "$TR_STACK_NAME" \
  -f deploy/standalone/compose.yml up -d --wait
node scripts/check-standalone-topology.mjs
pnpm run check:standalone-egress
```

Keep `TR_STACK_NAME` and the port variables exported in the shell for Compose
and both checks; putting them only in the private env file is insufficient for
the checks. `COMPOSE_PROJECT_NAME` and the explicit `-p` provide the same
selected project even if one override is accidentally omitted. The checks
reject a mismatch between `COMPOSE_PROJECT_NAME` and `TR_STACK_NAME`. Empty project
or port variables fail closed in the checks. The checks reject an unexpected project,
public or extra port binding, wrong loopback port, extra network attachment,
missing or extra mount, or elevated container privilege. Wizard-driven
`observe-stack` also compares the running indexer's three storage passwords
and secret and the proof server's bind source against the prepared private
`stack.env`; its observation records only a match flag, never secret values.
A direct topology check without that private input cannot attest the match.

The direct topology check requires Docker's **effective** loopback port mapping,
not just the requested `HostConfig.PortBindings`. Confirm that `docker port
<project>-node-1` exposes the intended `127.0.0.1` port and that the host can
reach it. On this macOS Docker Desktop development host, an internal-only
ledger bridge had requested loopback bindings but `NetworkSettings.Ports`
contained empty lists; the host RPC connection failed. Wizard `observe-stack`
may record this explicitly as `unpublished-install-access-required` after
checking the private inputs and the isolated bridge. That observation is **not**
host connectivity, local-ledger deployment, or offline-runtime evidence.
Wizard genesis observation requires either an effective direct mapping or a
v6 verified, source-pinned temporary installation relay. Older bundles and
the existing v3 smoke stack remain connectivity-only through the relay. Do
not add an egress-capable network
to the ledger services merely to make the check pass.
The v6 relay gate verifies the running image, mounted script hash, inherited
image environment, exact loopback publications, and selected bridge before and
after genesis preflight. Deployment reservation checks the same relay and the
plan's node and indexer URLs; a post-submission mismatch is an unknown outcome
that must be reconciled, never retried blindly. The proof-server endpoint is
still supplied by the operator's provider configuration and needs separate
review. Remove the relay before any offline-runtime qualification.
For a current setup, deployment reconciliation, verifier-key insertion and
reconciliation, committee preparation/submission/reconciliation, and recovery
approval recheck that same verified direct mapping or relay before using the
ledger; results are not recorded if access changes during readback. If the
temporary relay was removed, restore the **same verified** relay and ports for
those operations, then remove it again before testing egress-denied runtime.
Legacy read-only maintenance reconciliation remains forensic only and cannot
qualify a release. It does not recheck the current endpoint mapping, so a
legacy `observed` status is not authenticated deployment or release evidence.
A config-only render and a healthy new node do
not prove a local contract deployment, finalized readback, denied egress for
other processes, or release qualification. Review the new genesis and repeat
the first-run approvals for that instance. Never use `down -v` on either
project while its history is evidence.

The local Midnight network uses network ID `undeployed`, not `preprod`. The
dedicated smoke stack keeps node RPC, indexer, and proof-server services on
its internal bridge. On Docker Desktop, that bridge does **not** publish the
configured loopback ports to the host, even though Compose records the port
bindings. Probe service aliases from a container on the isolated network;
host-side preflight/deployment needs a separately controlled temporary access
path and cannot be counted as an offline journey while that path permits
egress. Do not expose these endpoints on public interfaces. Start and fund
local accounts before disabling egress. A local
proof server sees witness data and must remain inside the same trust boundary.

Before any deployment, have an operator approve a genesis hash through a
channel independent of the node being queried. Save the following public pin
as a regular JSON file, with the actual signed source SHA and approved hash:

```json
{
  "format": "tr-local-ledger-pin-v1",
  "networkId": "undeployed",
  "sourceRevision": "<40-character signed source SHA>",
  "rpcUrl": "http://127.0.0.1:29944",
  "expectedGenesisHash": "0x<64-character approved genesis hash>",
  "allowedHosts": ["127.0.0.1"]
}
```

Run `node scripts/local-ledger-preflight.mjs <approved-pin.json>` after the
integration package is built. It fails on a mismatched genesis or a finalized
head still at genesis. Its output is **local node observation only**, not an
independent finality proof, a contract deployment, or an approval of the pin.

The Trust Registry API and browser surfaces must use only the local network,
local DID/VC/status data, and locally persisted workspace state. An offline
deployment must authenticate the local network genesis, deploy the compiled
contract, persist its receipt, and read back the finalized contract image.
`deployLocalTrustRegistry` and `createLocalNetworkDeploymentActionReader`
provide a distinct `undeployed` path with an out-of-band genesis pin and an
explicit private-host allowlist for the checkpoint RPC and readback indexer
endpoints. The caller-supplied Midnight.js wallet, proving, and submission
providers are opaque to these helpers and **are not covered by that
allowlist**. Pin their endpoint configuration separately and enforce egress
denial for the complete process and container network; syntax checks on local
aliases do not prove where DNS resolves them. The indexer client's own redirect
handling is also outside the allowlist check, so egress denial is required
even for configured readback URLs. Use single-label aliases only on the
isolated container network. The public adapter still rejects `undeployed`;
do not relabel the local network as
Preprod. The local `prepareLocalNetworkCommitteeTransition`,
`submitLocalNetworkCommitteeTransition`, and
`reconcileLocalNetworkCommitteeTransition` helpers plan the Ledger 8
committee replacement from a finalized local image, reserve one durable
submission attempt, and inspect finalized readback without authorizing an
automatic retry. `readPostDeploymentLocalTrustRegistry` verifies the
post-transition image through the local reader. For an operator deployment,
use `deployLocalTrustRegistryOnce` with an exact source SHA and a
`FileDeploymentAttemptJournal` in a pre-provisioned private directory. It
checks that the installed contract's complete verifier-key inventory and file
hashes match the approved release manifest **before** reserving the attempt;
direct `deployLocalTrustRegistry` calls make the same check before broadcast.
This does not authenticate where the installed package came from, replace
the pinned install-artifact check, or eliminate a file-replacement race on a
writable installation. Keep the installed package read-only for the operator.
The journal reserves one attempt before the SDK call and retains the public receipt if the
adapter returns. A missing receipt after reservation means an unknown outcome,
not permission to redeploy; inspect the original intent and finalized local
chain state before a human recovery decision. These helpers do not install or
run a local node, prove egress denial, or demonstrate a live maintenance
transaction. The initial
single-key authority remains unsafe for release until a separately approved
committee is observed after finality. Durably record the deployment receipt,
committee approval, and journal before claiming a supported local deployment.
The operator's 1-of-3 committee choice is for a **development smoke only**;
the release helpers intentionally reject it as an approved multi-party
policy. Do not use that smoke result to close the RC maintenance gate. The
final threshold, three distinct public keys, custody assignments, and human
approval remain required before a release-qualified transition.

### Local deployment operator CLI

`node scripts/local-ledger-deploy.mjs <approved-plan.json>` is a guarded entry
point for a **real** local-ledger submission. Build the integration package and
verify the installed release artifact first. The plan is a private, absolute
path JSON file with exactly these fields (replace every placeholder):

```json
{
  "format": "tr-local-deployment-plan-v1",
  "sourceRevision": "<40-character approved git commit>",
  "network": {
    "networkId": "undeployed",
    "rpcUrl": "http://127.0.0.1:<checkpoint-port>",
    "indexerHttpUrl": "http://127.0.0.1:<indexer-port>/api/v4/graphql",
    "indexerWsUrl": "ws://127.0.0.1:<indexer-port>/api/v4/graphql/ws",
    "expectedGenesisHash": "0x<64-character independently approved hash>",
    "allowedHosts": ["127.0.0.1"]
  },
  "releaseManifestPath": "/absolute/read-only/release-manifest.json",
  "providerModulePath": "/absolute/read-only/approved-provider.mjs",
  "providerModuleSha256": "<64-character approved SHA-256 of module bytes>",
  "journalPath": "/absolute/private/deployment-attempt.json"
}
```

The approved provider module exports async `createLocalDeploymentMaterial({
network, releaseManifest })` and returns `{ bootstrap, providers,
contractMaintenanceSigningKey, stop? }`. It owns the funded local wallet and
all opaque Midnight.js provider endpoints; no wallet seed, signing key, or
mnemonic belongs in the plan or CLI output. The module is privileged code, not
a data file: review its transitive imports, approve its SHA-256, install it
read-only, and enforce process-level egress controls. A file hash checked
before dynamic import does not eliminate a replacement race on writable
storage. Use a pre-provisioned private journal directory and retain it with
the receipt and ledger evidence. The CLI checks the manifest source, module
hash, endpoint allowlist, and live genesis/finalized-head preflight before
loading the provider. The deployment helper checks installed verifier-key
assets before reserving its single attempt. The printed JSON is only a public
receipt and readback **status**, not proof that the image finalized or that
the maintenance authority is approved. An error or absent receipt after a
journal reservation is an unknown outcome; never rerun blindly. Inspect the
private journal and finalized local chain, then obtain a human recovery
decision. The accompanying unit tests mock providers and do not constitute
local deployment or offline qualification evidence.

The full constructor may exceed the local Ledger transaction block limit when
all release verifier keys are embedded at once. For a separately approved,
new installation only, the operator may change the plan format to
`tr-local-staged-deployment-plan-v1` and add
`"initialVerifierKeyName": "authorizeMaintainerAuditEvent"` (or another
approved name in the pinned release catalog). This is an explicit alternative,
not an automatic fallback from a failed full attempt. The staged plan uses a
distinct one-attempt intent hash, still verifies the complete installed key
catalog before reservation, and deploys exactly the chosen initial verifier
key. A successful finalized readback reports `staged-bootstrap-pending`, **not**
release qualification. The remaining keys must be installed in individually
journaled maintenance transactions, read back after finality, and matched to
the entire release manifest before committee transition and actor journeys.
The bootstrap CLI and first-run wizard do not perform that completion
automatically. Never
use a new staged plan to bypass an unresolved reservation from an earlier
attempt; reconcile the earlier journal and chain with a human recovery decision
first. The development-only public genesis wallet and 1-of-3 committee remain
unsuitable for release approval.

For a staged deployment with a finalized receipt, insert one remaining key at
a time with `node scripts/local-ledger-insert-verifier-key.mjs
<approved-insertion-plan.json>`. Each key uses the fixed private journal path
`verifier-<circuitName>.json` beside the deployment journal; never reuse or
rename a prior insertion journal. The circuit must be the next absent name in
sorted release-catalog order. The exact
insertion plan contains:

```json
{
  "format": "tr-local-verifier-key-insertion-plan-v1",
  "sourceRevision": "<40-character approved git commit>",
  "network": { "networkId": "undeployed", "rpcUrl": "http://127.0.0.1:<checkpoint-port>", "indexerHttpUrl": "http://127.0.0.1:<indexer-port>/api/v4/graphql", "indexerWsUrl": "ws://127.0.0.1:<indexer-port>/api/v4/graphql/ws", "expectedGenesisHash": "0x<approved hash>", "allowedHosts": ["127.0.0.1"] },
  "releaseManifestPath": "/absolute/read-only/release-manifest.json",
  "providerModulePath": "/absolute/read-only/approved-provider.mjs",
  "providerModuleSha256": "<approved SHA-256 of module bytes>",
  "deploymentJournalPath": "/absolute/private/deployment-attempt.json",
  "journalPath": "/absolute/private/verifier-<circuitName>.json",
  "initialVerifierKeyName": "<circuit in the staged deployment plan>",
  "circuitName": "<next absent release-catalog circuit>"
}
```

The CLI checks the original staged deployment approval and receipt, the local
genesis, the entire installed key catalog, and the finalized pre-insertion
image. It rejects changed or unexpected operations and changed bootstrap
authority, then durably reserves this circuit's attempt before calling the
Midnight SDK. It stores the public finalized transaction receipt and reads the
post-insertion image. `verified` means this circuit and the previously
installed subset match the pinned key hashes in the observed finalized image;
it does **not** mean the full catalog, committee, or RC is qualified. If the
readback lags, run the same plan with `--reconcile`, which never submits.
The CLI exits nonzero for pending, absent, mismatched, or ambiguous outcomes,
while still printing any public receipt it recovered.
`observed-without-receipt` means a key appeared after an ambiguous submission;
human transaction attribution and recovery approval are required. Do not
advance to another key until the prior journal and finalized state are
reconciled. `absent` only means a key is not yet visible after an attempt with
no receipt; it does not prove the transaction was never submitted. A successful
receipt with lagging readback remains `pending`. `failed-on-chain` retains the
public transaction receipt and requires operator investigation; neither state
authorizes deleting a journal or retrying automatically. The CLI's provider
module remains privileged and must be pinned,
reviewed, and run with egress controls. A verified full-key image, approved
committee transition, actor journeys, and independent security review are
still separate release gates. Unit tests for this CLI use injected providers
and are not local-ledger deployment evidence.
After the complete staged catalog is verified, committee-transition approval
must explicitly set `stagedVerifierKeyInstallation: true`. The expected
bootstrap authority counter is then the catalog size minus one; the full
constructor path still requires counter zero. Insertion receipts and journals
must be retained and reviewed before that transition. This mode is local-only.

### First-run setup wizard (initial slice)

The local CLI wraps the existing install verifier, genesis preflight, and
one-attempt deployment entry point. Create a **new private directory** for
each installation; do not reuse a prior attempt's directory:

```sh
node scripts/standalone-setup-wizard.mjs run /absolute/private/setup-directory
# Or run each step separately for an auditable operator session:
node scripts/standalone-setup-wizard.mjs init /absolute/private/setup-directory /absolute/verified-install-bundle
node scripts/standalone-setup-wizard.mjs prepare-stack /absolute/private/setup-directory tr-standalone-local-qualification 39944 38088 36300
# Review the selected project, loopback ports, and distinct volumes before starting it:
docker compose --env-file /absolute/private/setup-directory/stack.env -p tr-standalone-local-qualification -f /absolute/verified-install-bundle/compose.yml config -q
# After the operator starts the reviewed Compose plan, record live ledger-bridge checks:
node scripts/standalone-setup-wizard.mjs observe-stack /absolute/private/setup-directory
# Optional: collect the node's untrusted genesis candidate for independent review.
node scripts/standalone-setup-wizard.mjs collect-genesis-candidate /absolute/private/setup-directory
node scripts/standalone-setup-wizard.mjs observe /absolute/private/setup-directory /absolute/independently-reviewed-genesis-pin.json
node scripts/standalone-setup-wizard.mjs draft-genesis /absolute/private/setup-directory /absolute/genesis-review-metadata.json
# A human reviewer independently checks and signs the exact unsigned draft bytes.
node scripts/standalone-setup-wizard.mjs approve-genesis /absolute/private/setup-directory /absolute/private/setup-directory/genesis-approval.unsigned.json /absolute/reviewer-approval.sig /absolute/private/reviewer-public-keyring REVIEWER_SIGNING_KEY_FINGERPRINT
node scripts/standalone-setup-wizard.mjs draft-committee /absolute/private/setup-directory /absolute/committee-review-metadata.json
# Governance independently reviews the public keys, custody roles, and threshold before signing.
node scripts/standalone-setup-wizard.mjs approve-committee /absolute/private/setup-directory /absolute/private/setup-directory/committee-approval.unsigned.json /absolute/committee-approval.sig /absolute/private/governance-public-keyring GOVERNANCE_SIGNING_KEY_FINGERPRINT
node scripts/standalone-setup-wizard.mjs deploy /absolute/private/setup-directory /absolute/approved-deployment-plan.json
# Re-read a reserved staged deployment without submitting, if first readback lagged:
node scripts/standalone-setup-wizard.mjs reconcile-deploy /absolute/private/setup-directory /absolute/approved-deployment-plan.json
# After independent review of the finalized contract address and receipt:
node scripts/standalone-setup-wizard.mjs approve-committee-deployment /absolute/private/setup-directory /absolute/committee-deployment-approval.json /absolute/committee-deployment-approval.sig /absolute/private/governance-public-keyring GOVERNANCE_SIGNING_KEY_FINGERPRINT
# Only after a staged deployment receipt and finalized staged-bootstrap readback:
node scripts/standalone-setup-wizard.mjs insert-key /absolute/private/setup-directory /absolute/approved-insertion-plan.json
# Read-only recovery for that same plan; never resubmits:
node scripts/standalone-setup-wizard.mjs reconcile-key /absolute/private/setup-directory /absolute/approved-insertion-plan.json
# Only after every staged key has verified finalized readback:
node scripts/standalone-setup-wizard.mjs prepare-committee /absolute/private/setup-directory /absolute/committee-transition-request.json
# Save the prepare-committee JSON output as an exact signing-request file; sign dataToSignHex externally.
node scripts/standalone-setup-wizard.mjs submit-committee /absolute/private/setup-directory /absolute/committee-transition-request.json /absolute/committee-signing-request.json /absolute/committee-signature.json
# Read-only recovery; never submits or retries the maintenance transaction:
node scripts/standalone-setup-wizard.mjs reconcile-committee /absolute/private/setup-directory /absolute/committee-transition-request.json /absolute/committee-signing-request.json
node scripts/standalone-setup-wizard.mjs status /absolute/private/setup-directory
```

`prepare-stack` re-verifies a v3 install bundle, requires both current Compose
files to match its pinned bytes and its image inventory to match the base
Compose image references, and creates a mode-0600
`stack.env` with fresh random indexer credentials and the bundle's checked
proof-parameter path. Its output and setup record omit the credentials. It
does not start Compose. It refuses a project with existing containers, ledger
network, or node/indexer volumes; the operator must still confirm that the
loopback ports are unused before `up` and keep the Docker context unchanged.
Export the selected project and
port variables in the shell when running topology and egress checks; Compose's
`--env-file` alone does not configure those separate processes. Keep the
private file for restart and restore, and do not reuse it for another ledger.
An older v2 bundle remains historical smoke evidence, not a new wizard setup
input. A v3 bundle built from the chosen release source revision is still only
candidate bytes; it does not by itself support an RC qualification claim.
`observe-stack` checks the selected live project's topology and canary HTTPS/DNS
egress behavior, including prepared private-input matching and unchanged
bundled Compose bytes. For v3, it also matches the verified archive image IDs,
source-scoped offline tags, and Docker Compose's recorded bundle paths before
appending timestamped ledger-bridge evidence. Its probe runs a fresh throwaway
container on the same bridge using the verified node image ID, rather than
trusting a mutable local tag or directly probing the running node. A standalone CLI
invocation against a source-scoped offline stack must supply the same verified
bundle: `node scripts/check-standalone-egress.mjs <verified-bundle-directory>`.
A v3 setup record created before
image identities were recorded cannot be upgraded in place; begin a fresh
setup directory rather than replacing its evidence. At
most 20 pre-genesis observations are retained; investigate drift before that
limit instead of silently replacing earlier evidence. It refuses
to replace evidence after genesis observation or deployment begins. In the
interactive wizard, leaving stack preparation blank stops the session before
the genesis-pin prompt. Once a stack is prepared, the interactive wizard also
stops until the operator starts the reviewed stack and explicitly requests
`observe-stack`; for v3 installs, the separate `observe` command also refuses
a genesis pin until that stack observation exists. Legacy v2 records can still
be observed for historical smoke, not RC qualification. This step does not approve
genesis, attest actor egress, verify a contract readback, or qualify a release.

`collect-genesis-candidate` is an optional, non-overwriting first-run aid. It
rechecks the live v3-v6 stack and writes `genesis-candidate.untrusted.json` in the
private setup directory, recording the **node-reported** genesis hash,
finalized checkpoint, install source and inventory, and observer-script hash.
It accepts a ledger bridge whose requested host ports are unpublished on Docker
Desktop, but requires exactly the three ledger services attached. Disconnect
the temporary installation relay before collection, then reconnect that same
relay for the separately verified loopback preflight. Neither the unpublished
port allowance nor this candidate qualifies host access or offline egress.
It does not create an approved pin, change `localLedger` status, or authorize
deployment. An independent reviewer must compare the candidate with the
pinned chain specification through a channel other than this node, approve
the exact pin and source, and provide a detached signature and public GPG
fingerprint. Do not treat matching this candidate as independent verification.
The interactive `run` command offers this collection after `observe-stack`
only when the operator types `COLLECT`; it then separately asks for an
independently reviewed pin JSON. Leave that second prompt blank until the
reviewer has supplied the pin. Re-running collection does not overwrite an
existing candidate; preserve the first file and investigate any changed node
observation in a separate evidence record.

For the pinned local node image, `CFG_PRESET=dev` selects the embedded
`/res/cfg/dev.toml`, which references
`/res/genesis/genesis_block_undeployed.mn` and
`/res/genesis/genesis_state_undeployed.mn`. The operator can give the reviewer
the image digest, these file hashes, and the digest of
`/midnight-node build-spec --dev --raw --disable-default-bootnode` output as
reproducibility evidence. All of those values still come from the running
image; they are **not** an independent source for the approved genesis hash.
The reviewer must obtain the reviewed chain specification and node artifact
provenance through a separately controlled channel, derive or verify its
genesis hash independently, then sign the exact pin and source reference.

`draft-genesis` accepts a JSON object with exactly `reviewerFingerprint`,
`reviewedReference`, and a human-supplied ISO `approvedAt` timestamp.
`draft-committee` accepts those fields plus
`maintenancePolicy` and `custodians` in the approval shapes below. Both commands
derive the source, install, and genesis binding from the private setup record;
they create mode-0600 `*.unsigned.json` files in that directory without
overwriting an earlier draft. The printed state is
`unsigned-human-review-required`, not approval. Reviewers must independently
verify the references, committee public keys, threshold, and custody records,
including the approval time, then sign the **exact bytes** of the draft they
accept. The operator passes that
same file and detached signature to `approve-genesis` or `approve-committee`.
The wizard does not create reviewer authority, private keys, or signatures.
Every signed genesis, committee, deployment-binding, and no-journal recovery
decision requires a canonical UTC ISO approval time and an independently
reviewed non-`demo:` reference; alternate time spellings and synthetic demo
references are rejected before signature verification.
Signed approval JSON must be either compact JSON (`JSON.stringify(value)`)
or the wizard's two-space-indented draft with one trailing newline. The wizard
rejects alternate serialization and duplicate keys before verifying the
signature; reviewers should sign the exact generated draft bytes whenever a
draft command is available.

New setups require an install bundle with verified runtime Compose and offline
Compose pins (v3 or later); a historical v2 bundle cannot initialize a new
deployment. Existing v2 records cannot draft or accept genesis approval or
reserve a deployment, even if they contain a setup ID; recreate them from a
current bundle and observe a verified stack. Historical test
fixtures are not standalone deployment evidence.

The wizard verifies staged bytes, checks that the pin and deployment plan
match the installed source and observed genesis, and requires a detached
reviewer signature before deployment. The signed JSON has exactly these fields:

```json
{
  "format": "tr-local-genesis-approval-v1",
  "setupId": "<random setup ID from setup-record.json>",
  "stackProject": "<prepared Compose project from setup-record.json>",
  "sourceRevision": "<signed source SHA from setup-record.json>",
  "installInventorySha256": "<inventory hash from setup-record.json>",
  "networkId": "undeployed",
  "pinSha256": "<candidate pin hash from setup-record.json>",
  "expectedGenesisHash": "0x<approved 64-character genesis hash>",
  "rpcUrl": "<observed loopback RPC URL>",
  "reviewerFingerprint": "<40-character uppercase GPG signing-key fingerprint>",
  "reviewedReference": "<independent chain-spec or genesis evidence reference>",
  "approvedAt": "<ISO-8601 time after setup initialization>"
}
```

The `setupId` and `stackProject` bind this signature to one private first-run
setup and its isolated ledger stack; an approval drafted for another setup
cannot be reused. Sign a newly generated draft for a new installation rather
than copying an earlier approval document. The wizard rechecks the live
direct-loopback topology after genesis preflight, and topology plus exact
indexer endpoints immediately before submitting a deployment.

The reviewer compares the candidate genesis to independently obtained
chain-spec evidence, signs the exact JSON bytes on a separate trusted system,
and sends the detached signature and public signing key to the operator.
An existing GitHub-registered **GPG signing key** may be used for this human
review. GitHub registration or a Verified commit is not the approval: the
reviewer must still sign the exact `genesis-approval.unsigned.json` bytes with
that key. Select the full 40-hex-character primary signing-key fingerprint,
not its short key ID or an encryption subkey; confirm the key owner and
fingerprint through a channel independent of the node and the GitHub key
listing. Do not export or send a secret key. For example, on the reviewer's
trusted signing system, after inspecting the draft and independent evidence:

```sh
gpg --local-user REVIEWER_SIGNING_KEY_FINGERPRINT --armor --detach-sign \
  --output genesis-approval.sig genesis-approval.unsigned.json
gpg --verify genesis-approval.sig genesis-approval.unsigned.json
```

The verifier accepts a signing subkey only when GnuPG reports the pinned
primary-key fingerprint and the `GOODSIG` key ID or fingerprint matches the
actual signer.
It requires a detached binary-document signature using SHA-256, SHA-384, or
SHA-512; ASCII armoring of that detached signature is accepted. It rejects an
expired or revoked signing key or signature. A `KEYEXPIRED` status alone does
not cause rejection; an expired signing key is rejected through `EXPKEYSIG`.
The operator must refresh the approved public-key export or keyring before
verification, because an old export cannot reveal a later revocation. The signature's
creation time must be at or after the draft's `approvedAt` time; set that
timestamp immediately before signing on a clock-synchronized trusted system.
GnuPG signature time is signer-controlled metadata, not an independent trusted
timestamp or proof that the review occurred.

The `reviewedReference` in the draft must identify the independently reviewed
chain specification or reproducible genesis evidence and its immutable digest
(a ticket or document ID is optional). For a format-only illustration, run
`node scripts/demo-genesis-reference.mjs standalone` or
`node scripts/demo-genesis-reference.mjs preview`. These commands hash distinct,
synthetic chain-spec fixtures and print `demo:` references. They do not contact
either network, read a real genesis, produce a signed approval, or qualify a
release. The wizard rejects their `demo:` references. The node-generated
candidate packet by itself is not such a reference. If that independent
reference is not available, leave the draft unsigned and deployment blocked;
do not substitute chat approval or a GitHub commit signature.
The operator obtains the expected fingerprint through an independently
approved channel and runs `approve-genesis` with either the reviewer's
armored **public-key export** (`gpg --armor --export FINGERPRINT >
reviewer-public.asc`) or a local GPG keyring directory. The wizard imports the
public export into a short-lived isolated verification home; it never needs
the reviewer's secret key. For a directory, pre-create it with mode `0700`
and import the public key there with `gpg --homedir
/absolute/private/reviewer-public-keyring --import reviewer-public.asc`. The
directory must contain `pubring.kbx`; keyboxd-only and legacy `pubring.gpg`
homes are not accepted. Both forms pin the full reviewer fingerprint.
The wizard does not download keys or establish
reviewer authority from a typed fingerprint: the release owner must separately
verify the key owner and the provenance of `reviewedReference`. It checks
the signature, signer fingerprint, source, inventory, genesis, and setup time,
then preserves the signed bytes in the private setup record. An observation
cannot be replaced after approval.

The governance reviewer can sign a separate first-setup **release roster**
after genesis approval. Its exact JSON shape is:

```json
{
  "format": "tr-local-committee-approval-v1",
  "sourceRevision": "<signed source SHA from setup-record.json>",
  "installInventorySha256": "<inventory hash from setup-record.json>",
  "genesisApprovalSha256": "<signed genesis document hash from setup-record.json>",
  "networkId": "undeployed",
  "expectedGenesisHash": "0x<approved 64-character genesis hash>",
  "reviewerFingerprint": "<40-character uppercase governance signing-key fingerprint>",
  "reviewedReference": "<governance decision or minutes reference>",
  "approvedAt": "<ISO-8601 time after genesis approval>",
  "maintenancePolicy": {
    "mode": "committee",
    "threshold": 2,
    "verifyingKeys": ["0x<key-1>", "0x<key-2>", "0x<key-3>"]
  },
  "custodians": [
    { "verifyingKey": "0x<key-1>", "holderRole": "maintainer-1", "custodyReference": "<custody record>" },
    { "verifyingKey": "0x<key-2>", "holderRole": "maintainer-2", "custodyReference": "<custody record>" },
    { "verifyingKey": "0x<key-3>", "holderRole": "maintainer-3", "custodyReference": "<custody record>" }
  ]
}
```

Replace all placeholders with exact approved values. The signed roster must
contain at least three distinct canonical, Ledger-valid Schnorr public keys,
a threshold of at least two, and distinct custody roles matched in key order. The 1-of-3 choice is
**smoke-only** and intentionally fails this release approval step. As with
genesis, the setup host verifies the detached signature against an
operator-pinned reviewer public key; the release owner must separately verify
the governance reviewer's authority and custody evidence. A recorded roster
is required **before deployment reservation**: deferring it stops the wizard
before `DEPLOY ONCE`, so a finalized contract cannot strand the setup under
the bootstrap maintenance key. It does not submit or verify a contract
maintenance transition. The wizard shows
`roster-signature-verified-deployment-binding-pending` until the governance
reviewer signs a second approval for the actual deployment. That approval has
exactly this JSON shape:

```json
{
  "format": "tr-local-committee-deployment-approval-v1",
  "sourceRevision": "<approved 40-character source SHA>",
  "committeeApprovalSha256": "<signed roster document hash from setup-record.json>",
  "deploymentPlanSha256": "<reserved staged plan hash from setup-record.json>",
  "deploymentReceipt": {
    "networkId": "undeployed",
    "contractAddress": "0x<finalized contract address>",
    "txId": "<deployment transaction ID>",
    "blockHash": "0x<deployment block hash>",
    "blockHeight": 1
  },
  "releaseManifestSha256": "<verified bundle release manifest hash>",
  "expectedGenesisHash": "0x<approved local genesis hash>",
  "reviewerFingerprint": "<same pinned governance reviewer fingerprint as the roster>",
  "reviewedReference": "<independent deployment review or minutes reference>",
  "approvedAt": "<canonical UTC ISO-8601 time after deployment reservation>"
}
```

The reviewer independently inspects the plan, receipt, finalized on-ledger
contract address and genesis, and pinned manifest before signing the exact
bytes. The wizard verifies the detached signature against the pinned governance
key, compares the receipt, source, plan, genesis, roster, and manifest against
the preserved setup record, and retains the signed bytes privately. It
does not re-read the chain at approval time or establish reviewer authority
or independent inclusion by itself. A missing or ambiguous deployment receipt
cannot receive this approval, and approval never authorizes a retry. Once
recorded, `status` reports
`deployment-bound-roster-signature-verified-transition-pending`; only then can
the transition be prepared. Finalized maintenance readback and the other RC
gates remain pending.
If an older setup record already has a maintenance attempt, the wizard will
not accept a retrospective deployment approval. It still permits read-only
reconciliation of that saved attempt without the new binding; it will not
prepare, resubmit, or automatically recover a new attempt from it. Preserve
the original journal and obtain an operator-reviewed migration decision.

`prepare-committee` is that flow's **read-only signing step**, not the
submission. Its public request JSON has exactly these fields; the bootstrap
and governance values must reflect the operator-approved deployment and the
current finalized ledger, not the example values below:

```json
{
  "format": "tr-local-committee-transition-request-v1",
  "sourceRevision": "<approved 40-character source SHA>",
  "bootstrapMaintenanceVerifyingKey": "0x<approved bootstrap maintenance key>",
  "expiresAt": "<ISO-8601 time within the next ten minutes>",
  "bootstrap": {
    "registryId": "<approved registry ID>",
    "registryDidCommitment": "0x<bytes32>",
    "governancePolicyCommitment": "0x<bytes32>",
    "maintainerId": "0x<bytes32>",
    "maintainerDidCommitment": "0x<bytes32>",
    "maintainerKeyId": "0x<bytes32>",
    "maintainerPublicKey": { "x": "<decimal>", "y": "<decimal>" },
    "maintainerThreshold": "<decimal>"
  },
  "governance": {
    "policyCommitment": "0x<bytes32>",
    "policyVersion": "<decimal>",
    "actionSequence": "<decimal>",
    "maintainerThreshold": "<decimal>",
    "activeMaintainerCount": "<decimal>"
  }
}
```

The wizard rechecks the signed roster and deployment binding, verified install bundle and
release manifest, original staged receipt, and every per-key `verified`
readback. The local finality reader then checks the complete current
verifier-key image, bootstrap authority counter, approved 2-of-3-or-stronger
committee, and governance pins before the wizard emits `dataToSignHex` with
the `updateSha256`, finalized block hash, roster approval hash, and deployment
binding approval hash. The reservation also pins the latter. Preserve these
pins with the separately signed bytes: a later local submission must reject a
fresh plan if its update hash differs. A newer finalized head is allowed only
when a fresh finalized readback still matches the approved full registry image
and exact signable update; the journal retains both the originally approved
checkpoint and the current submission checkpoint. Neither
the request nor its output contains a private key. The signature file has
exactly this shape:

```json
{
  "format": "tr-local-committee-signature-v1",
  "updateSha256": "<updateSha256 from the saved signing request>",
  "signature": "0x<128 lowercase hex characters from an external bootstrap signer>"
}
```

`submit-committee` re-prepares against the live finalized image, requires the
saved signing request to match every field except the advancing finalized-head
hash, and verifies the bootstrap signature
before reservation, and records a one-attempt private maintenance journal
before proving or submitting. A changed signable payload requires a new
signing request and signature. If a caught preflight error leaves **no journal
reservation**, the wizard records `aborted-before-journal` and permits an
explicit new attempt; it retains the aborted record in history. A present or
unreadable journal is **unknown**, never permission to retry.
`reconcile-committee` uses the original
request and signing-request hashes, journal, and finalized readback without
submitting. A returned transaction ID is journal-attributed; it is not
independent inclusion evidence. The wizard never marks the release qualified
merely because this transition is observed. Keep the bootstrap key under
approved custody; do not use the public smoke wallet or 1-of-3 smoke roster
as a release authority.

If the process exits between the wizard reservation and the journal write,
reconciliation reports `recovery-required-no-journal`. An absent journal after
a crash is not proof that no transaction was sent or that a record was not
lost. The wizard will not retry this state automatically: preserve the setup
directory, inspect the finalized chain and expiry, and obtain an independent
human recovery decision before any new installation attempt. After the
original signing window has expired for at least ten minutes, the approved
governance reviewer can sign this exact decision document with their pinned
GPG key (the same reviewer key approved for the committee roster):

```json
{
  "format": "tr-local-maintenance-no-journal-recovery-v1",
  "decision": "authorize-new-attempt-after-absent-journal",
  "sourceRevision": "<source revision in setup status>",
  "requestSha256": "<original request hash from setup status>",
  "signingRequestSha256": "<original signing-request hash from setup status>",
  "updateSha256": "<original update hash from setup status>",
  "approvedFinalizedBlockHash": "<original finalized checkpoint from setup status>",
  "recoveryFinalizedBlockHash": "<later finalized checkpoint independently inspected by the reviewer>",
  "expiredAt": "<original request expiry in ISO-8601 UTC>",
  "reviewerFingerprint": "<pinned governance signing fingerprint>",
  "reviewedReference": "<bounded reference to independent finalized-chain and journal inspection>",
  "approvedAt": "<reviewer approval time in ISO-8601 UTC>"
}
```

Use the original request and signing-request files, not replacements, for
approval. The reviewer must independently inspect the journal, mempool and
finalized chain, and establish that the original intent expired in **ledger
time** without a maintenance transition. A changed finalized head alone is
not proof. Account for local clock skew relative to the node. The wizard
requires a nonzero reviewer-attested later checkpoint, independently sees an
advancing finalized head with the same signable registry image, finds no
journal, and verifies the detached signature before recording this decision.
It cannot prove that the reviewer-attested checkpoint is an ancestor of its
live head; that is part of the independent review evidence:

```sh
node scripts/standalone-setup-wizard.mjs approve-committee-recovery /absolute/private/setup-directory /absolute/original-committee-transition-request.json /absolute/original-committee-signing-request.json /absolute/recovery-decision.json /absolute/recovery-decision.sig /absolute/private/governance-public-keyring GOVERNANCE_SIGNING_KEY_FINGERPRINT
```

Approval unlocks only a new attempt. Create a request with a later expiry,
run `prepare-committee` again against the live finalized head, save its
output without changing the checkpoint hash, and call
`submit-committee` with the external
bootstrap signature for the approved update. The maintenance update hash does
**not** include the intent expiry: a later expiry does not cryptographically
invalidate the original signature, and an old signature file remains usable
while the bootstrap counter is unchanged. Keep that file under approved key
custody, or securely destroy it after the committee transition finalizes.
The safety condition for retry is the independent finding that the earlier
intent expired on-ledger and the authority counter stayed unchanged, not a
claim of fresh signature bytes. The recovered attempt remains in bounded
history; the wizard never resubmits it or treats approval as evidence of a
finalized transition. If independent inspection
cannot rule out an unknown broadcast, retain the blocked state and escalate
to the operator/security reviewer instead of signing the decision. Reconciliation
history and `maintenanceTransitionAlert` retain conflicts even if later reads
temporarily fail or show the expected authority. If a journal-recorded
transaction ID is lost, the status reports a conflict rather than treating it
as a harmless pre-journal abort. A broadcast ID returned during a failed
response write is retained as `reportedTxId`, not accepted as inclusion proof.

The pinned provider module must export `createLocalMaintenanceMaterial` to
return contract providers and optional `stop()` cleanup. This factory must
not load or create the bootstrap maintenance signing key; the signer supplies
only the external signature file. The documented public-wallet smoke provider
implements this keyless maintenance factory, but remains development-only.

The wizard saves a mode-0600 setup record in a mode-0700 directory. It
reserves a deployment attempt **before**
calling the provider. If the process exits, the provider fails, or the receipt
is unclear, do not invoke `deploy` again against that setup; inspect the
deployment journal and finalized chain, then obtain a human recovery decision.
If `status` reports `setupLock: present-inspect-before-removal` after an
interruption, first establish that no wizard process is running, then inspect
the setup record, one-attempt journal, and finalized chain. Do not remove a
stale lock or create a new setup solely to repeat an uncertain submission.
For staged deployment, `insert-key` also requires the original recorded
deployment receipt and `staged-bootstrap-pending` finalized readback. It binds
the insertion plan to the exact approved source, genesis, RPC and indexer
endpoints, provider module hash, staged initial key, original deployment
journal, and verified bundle manifest before making a separate one-attempt
reservation. The insertion CLI rechecks the manifest bytes and compares the
journal's deployment receipt with the wizard's recorded receipt before any
submission. The underlying insertion CLI still checks the live finalized
image and per-circuit journal. A pending, failed, or ambiguous key blocks the
next key; use `reconcile-key` with the **same plan** for read-only observation.
Neither command deletes a reservation or authorizes a retry. The wizard reports
per-key states and retains any public receipt recovered from an ambiguous
submission, but never upgrades `releaseQualified` from these observations.
`insert-key` and `reconcile-key` exit nonzero unless the result is `verified`.
Even a failure known to occur before submission leaves a wizard reservation
that requires operator investigation; do not remove it or create a fresh setup
to bypass recovery.
If the initial staged deployment returned a receipt but its first finalized
readback was `pending` or `unavailable`, use `reconcile-deploy` with the
**same original plan bytes**. It rechecks the pinned source, genesis, provider
module, bundle manifest, deployment journal, and any receipt already recorded
by the wizard, then reads the one-key image at a genesis-pinned finalized
checkpoint. It updates the local observation only if a complete public receipt
is present; `staged-bootstrap-pending` means the expected one-key bootstrap
was observed, **not** full-key or release qualification. If the journal has no
submission receipt, reconciliation reports `unknown-no-receipt` and leaves
the setup reserved; absence of a receipt does not prove absence of submission.
The hash-pinned provider module may initialize or synchronize local wallet
state while assembling the approved bootstrap material; this code path does
not call an SDK submit method, but the provider module still requires review.
The receipt's transaction ID, block hash, and height come from the private
journal and are not independently proven included by the state readback;
the reconciliation result labels this attribution explicitly. Once a
staged-bootstrap readback is recorded or any key insertion has started,
`reconcile-deploy` refuses to run, so a later indexer lag or installed key
cannot downgrade the recorded bootstrap. Use `reconcile-key` for key recovery.
The private setup record retains earlier readback observations, including
`mismatch` and `invalid-image`, instead of overwriting that audit history with
a later pending observation.
If the setup record already contained a receipt but the journal no longer
does, reconciliation fails rather than downgrading it to unknown; preserve both
records for investigation.
This command cannot reconcile the earlier unresolved **full-constructor**
development attempt. Preserve its journal and seek a human recovery decision;
do not hand-edit the record or submit a second deployment. A
`failed-on-chain`, `mismatch`, or
`observed-without-receipt` key also requires an explicit human recovery
decision; it cannot be skipped to install later keys.
The wizard does not generate or itself approve a genesis hash, provider module,
funded wallet, committee roster, threshold, or key custody. A public local
genesis wallet and 1-of-3 committee are permitted only for a development
smoke, never as RC approval. Final committee approval must be collected during
first setup from responsible humans, not inferred from a typed acknowledgement.
Later wizard slices must execute finalized maintenance readback, offline actor
journeys, and recovery qualification.
`status` deliberately keeps these gates pending even if deployment returns a
receipt; it does not produce a release-qualified verdict.

For a **development-only** real-ledger deployment smoke, the repository-owned
`scripts/local-smoke-provider.mjs` implements the provider-module interface.
Use it only against the dedicated `undeployed` loopback stack, with the public
local genesis wallet seed documented by `midnight-examples`. Set
`TR_SMOKE_WALLET_SEED` to that public seed, `TR_SMOKE_STATE_DIR` to the private
setup directory, and `TR_SMOKE_PROOF_URL` to the temporary loopback proof
relay. The module rejects public-network IDs, non-loopback endpoints, a
different wallet seed, and a non-private state directory. It saves a random
bootstrap maintenance signing key as `smoke-maintenance-key` (mode 0600)
before wallet submission. Keep that file with the one-attempt journal for
reconciliation; do not commit, distribute, or log it. It uses an in-memory
contract private-state provider and is **not** a production wallet/custody or
restart/restore solution. The approved deployment plan must point to this
module by absolute path and its exact SHA-256, and to the verified bundle's
release manifest. The wizard binds that manifest and the plan's network to
the observed setup before reserving the attempt. Running this smoke can
produce local-ledger evidence only after a real receipt and finalized readback;
the 1-of-3 transition and release approvals remain separate, open gates.

The dedicated internal Docker network used in development does not expose its
configured loopback ports to the host on the tested Docker Desktop setup.
For an **online installation or deployment window only**, run a temporary
fixed-destination relay using the already pinned node image, then attach that
one container to the selected internal ledger network. The relay has no configurable
upstream destinations. Select three unused host loopback ports distinct from
both Compose projects' published ports; the example below uses `40944` for
node RPC, `48088` for the indexer, and `46300` for the proof server. Use those
host ports in the operator's approved endpoint plan and separately pin the
opaque wallet provider endpoints. Stop and remove
the relay before the offline runtime test; the relay has a `bridge` attachment
and is **not** evidence of egress denial.
Use the absolute canonical `install-relay.py` path returned by the verified v6
bundle for the read-only mount; a symlink or differently spelled source path
fails the live relay gate.

```sh
export TR_STACK_NAME=tr-standalone-local-qualification
export TR_RELAY_NAME="${TR_STACK_NAME}-install-relay"
docker run -d --pull=never --name "$TR_RELAY_NAME" --network bridge \
  --publish 127.0.0.1:40944:30944 \
  --publish 127.0.0.1:48088:38088 \
  --publish 127.0.0.1:46300:36300 \
  --mount type=bind,src="<verified-v6-bundle>/install-relay.py",dst=/relay.py,readonly \
  --entrypoint /usr/bin/python3 \
  midnightntwrk/midnight-node@sha256:c3e46f8beff308b352813cd8904f6480c331504e09060abd671b8a32e1255220 \
  /relay.py
docker network connect "${TR_STACK_NAME}_ledger" "$TR_RELAY_NAME"
# Perform approved installation/deployment checks, then remove the access path.
docker stop "$TR_RELAY_NAME"
docker rm "$TR_RELAY_NAME"
env TR_STACK_NAME="$TR_STACK_NAME" TR_NODE_PORT=39944 TR_INDEXER_PORT=38088 \
  TR_PROOF_PORT=36300 node scripts/check-standalone-topology.mjs
```

Earlier smoke host checks returned the pinned genesis, GraphQL `Query`, and
proof-server version `8.1.0` through the relay. Recheck the selected ports and
endpoints for each new installation. Such checks establish connectivity only.
Do not leave the relay running during egress-denied actor journeys.

When a local deployment attempt has a reservation but **no submitted receipt**,
the operator can capture a read-only, node-pinned finalized-chain scan during
that same temporary relay window:

```sh
node scripts/scan-local-deployment-attempt.mjs \
  /absolute/private/approved-deployment-plan.json START_HEIGHT_BEFORE_RESERVATION
```

Choose a start height whose indexed timestamp precedes the reservation by a
sufficient margin. The captured finalized head must be at least one hour after
the reservation; this minimum does not prove that every provider process has
stopped or every transaction lifetime has elapsed. The
scanner reads the approved plan and original private reservation, checks their
source revision and genesis against the live node, captures one finalized head,
and checks every indexed block hash against a batched node hash query, along
with the indexer's parent links. **Transaction enumeration comes only from
the indexer**; the scanner does not decode node block extrinsics to establish
indexer completeness. It records indexer-reported transaction count and
contract-deployment candidates, the pending-extrinsic count, and the best and
finalized heights at scan end so any unscanned newer blocks are visible. The
range must contain at most 10,000
blocks; otherwise preserve the attempt and use a separately reviewed archival
scan. The scanner rejects an existing submitted receipt: use receipt-based
reconciliation instead. It does not load wallet material, submit a transaction,
modify a journal, or approve another attempt. An empty result is **not** proof
that no transaction was ever broadcast, that a later block cannot contain it,
or that the operator may retry. Independently inspect provider history,
finality, mempool, and any candidate contract state before a signed recovery
decision. Stop and remove the relay after collecting the observation.

Run `node scripts/check-standalone-topology.mjs` against the selected
`TR_STACK_NAME` project (the default is `tr-standalone-local-smoke`) after the
offline cold start. It reads
Docker metadata without changing containers or volumes and fails on extra
network attachments, missing persistence mounts, a writable proof cache,
fetch-enabled proof server, non-loopback or unexpected published ports, or
non-digest-pinned images. Its JSON deliberately
reports `egressDenied: "not-verified"` and `actorJourneys: "not-run"`: an
internal bridge is a useful precondition, not proof of denied external DNS or
egress for the wallet, API, browser, and backup processes. Capture firewall
logs and run real actor journeys under the release egress policy separately.

The topology check also requires the network's complete attachment list to
match the three pinned services. A temporary installation relay or another
container attached to the ledger bridge fails the check. To test one
outbound path with a positive control, while Docker's normal bridge can reach
the public internet and the relay is absent, run:

```sh
pnpm run check:standalone-egress
```

This contacts the external third-party host `example.com` from a restricted
ephemeral copy of the pinned node image on Docker's normal bridge. The same
IP-pinned HTTPS request must then fail on the dedicated internal bridge,
and the canary's DNS lookup must fail there as well. The control must have a
broad outbound route; the internal probe must have no `/0` or `/1` route.
The isolated probes target the observed Docker network ID, which must remain
the same before and after the probe; the wizard also requires its topology and
egress observations to agree on that ID. A replaced ledger bridge invalidates
the result. The command changes no ledger data or service mounts. Its evidence is limited
to this canary and the ledger bridge. It does not verify wallet, API, browser,
backup, other host egress paths, or actor journeys, and it does not replace
firewall logs or an offline end-to-end run.

The current API's file-backed
simulator mode may be used for demonstrations, but must be labeled fixture-only.
The genesis pin alone may not distinguish a fresh local node from one reset
to the same chain specification: persist and verify chain state, receipts,
and finalized history across restarts. A node without a progressing finalized
head yields `pending`, not qualification evidence.

### Ledger-bridge restart observation

After recording a v3-v6 `observe-stack` result, capture one non-overwriting
baseline in the private setup directory. Restart the selected project's
services **one at a time**, checking health between commands, then verify:

```sh
node scripts/check-standalone-restart.mjs capture /absolute/private/setup-directory
docker restart <selected-project>-node-1
# Wait for the node health check, then restart the indexer and wait for health.
docker restart <selected-project>-indexer-1
docker restart <selected-project>-proof-server-1
node scripts/check-standalone-restart.mjs verify /absolute/private/setup-directory
```

The observer rechecks the verified bundle, private prepared inputs, live
container image IDs and Compose paths, and the same named volumes. Verification
requires each service's container ID to remain stable and start time to advance, the earlier finalized block to
retain its hash at the same height, and finality to progress afterward. It
also binds the ledger network ID and observed host-port access mode across
both snapshots. On Docker Desktop, an unpublished requested loopback port is
accepted for this **ledger-only** observation; it is not evidence that the host
can reach the ledger, that the installation relay is present, or that offline
egress is denied. Disconnect any temporary relay before each snapshot so the
bridge contains exactly the three pinned services. It records the observer
script hash separately from the bundle source SHA. The
private `restart-baseline.json` and `restart-verification.json` files are
created once with mode 0600; do not overwrite them to retry a failure. Retain
the explicit restart command log and investigate failed or ambiguous results.
Never use `down -v` on a ledger whose history is evidence.
The wizard's `status` command checks these private evidence files without
querying Docker: `restartObservation` can report
`self-attested-ledger-bridge-only` with both finalized heights and an explicit
`pre-deployment-smoke`, setup-recorded deployment, or unbound deployment-state
marker. Only a valid staged-bootstrap readback receives the recorded-deployment
label; unknown, mismatched, and legacy states remain unbound. This is a
consistency check of operator-held files, not proof that Docker/RPC was
observed independently. `restartRestore` remains `pending`. A changed
baseline, mismatched verification, or evidence bound to another setup reports
`invalid-evidence-investigate` without hiding deployment or maintenance alerts.
Preserve the files for investigation instead of recapturing. Evidence files
are published atomically only after a private temporary file is synced, so an
interrupted write cannot leave a half-written final path.
If deployment changes between baseline and verification, the comparison fails
closed. Preserve that baseline as failed evidence and use a fresh private setup
directory under an approved recovery procedure for a new observation; do not
overwrite or delete the original evidence.

This is **ledger-bridge continuity only**. A pre-deployment run is a development
smoke, not RC evidence. Even after deployment, this helper does not read back
the contract, wallet keys, API state, browser journeys, or backup media; it
does not exercise cross-host restore, prove independent service restarts from
the command log alone, or close the restart/recovery release gate.

The first dedicated local-ledger b3 observation was captured before contract
deployment. Its finalized-history continuity is a development smoke only;
it cannot be relabelled after deployment. A release observation needs a new,
approved setup and post-deployment baseline, plus the separate contract,
wallet, API, and recovery readbacks described above.

### Distinct-project restore readback

After deployment and before a separately approved backup, capture a
non-overwriting finalized checkpoint in the source setup directory. Restore
the operator-held backup to a **different isolated project and setup
directory**, then read the destination's finalized chain:

```sh
node scripts/check-standalone-restore.mjs capture /absolute/private/source-setup
# Operator stops services, backs up, transfers, and restores node/indexer,
# wallet, API, and contract state under an approved custody procedure.
node scripts/check-standalone-restore.mjs verify /absolute/private/source-setup /absolute/private/destination-setup
```

The readback rechecks each project's verified install bundle and live ledger
topology. It requires the same source revision, observer and install inventory,
genesis, and historical finalized block hash, with a different project,
network, and three container identities. Destination finality must advance
beyond the source checkpoint. The source snapshot and destination result are
private, atomically published one-write files. Source capture requires a
setup-recorded staged-bootstrap deployment receipt no later than its finalized
checkpoint, with node-reported block hash at the receipt height matching the
recorded receipt hash. Pre-deployment smoke cannot consume that source slot. Verification
binds both snapshots to their own private setup records. A fresh restore
destination may have no deployment receipt in its setup record, so the result
remains `pre-deployment-or-unbound-smoke` until separate contract and wallet
readback is supplied. This consistency check does not independently read
contract state. Preserve the files on any failure instead of recapturing
or resetting volumes.

This is only **distinct-project ledger continuity**. The script cannot prove
that a backup was made, transferred to another host, or held under approved
custody. It does not read contract state, wallet keys, API data, or transaction
journals; these require separate post-restore evidence. Running its tests
with injected snapshots is not local deployment or restore evidence.

## Acceptance Test Before Claiming Support

1. Complete installation online, then block external DNS and egress while
   preserving loopback and the isolated local service network. Restart all
   services from pinned local images and package bytes without network pulls.
2. Deploy to the local Midnight ledger and verify the network/genesis pin,
   contract address, constructor state, verifier-key hashes, and maintenance
   authority after finality. Exercise the approved maintenance model rather
   than relying on a default single-key authority.
3. Run issuer, verifier, auditor, maintainer, and recognition actor journeys
   through the self-hosted API and browser surfaces. Test wallet funding,
   proofs, DID resolution, status checks, finalized evidence, and TRQP
   projection with no public endpoint calls. Reject stale, substituted, or
   unavailable trust data rather than silently treating it as valid.
4. Restart node, indexer, prover, and API independently. Verify persistent
   keys, wallet state, ledger, receipts, and historical evidence survive.
   Exercise backup and restore on another isolated host, including conflict
   and ambiguous-transaction recovery.
5. Capture egress-deny logs, exact source/image/package hashes, test reports,
   operator instructions, and an independent security review. Do not call the
   profile supported until these checks pass on a clean install.

The archived [Midnight local-dev project](https://github.com/midnightntwrk/midnight-local-dev)
documents a historical container and funding flow, but points to
[`midnight-examples`](https://github.com/midnightntwrk/midnight-examples)
for maintained tooling. Development genesis wallets and mnemonic examples are
not production secrets or public-network security guidance.

## Evidence Ledger And Stop Rules

The release owner must bind every item below to one signed source SHA and one
reviewed install manifest. Preserve raw receipts, finalized checkpoint hashes,
container image digests, package hashes, commands, timestamps, and reviewer
decisions in an access-controlled evidence bundle. Redact secrets, but do not
replace network or transaction identifiers with simulator identifiers.

| Gate | Evidence required | Owner input or stop condition |
| --- | --- | --- |
| Pinned installation | Reviewed local-dev source revision, exact image digests, package tarball hashes, compiler/toolchain versions, SBOM, and verified clean-install record | Operator approves artifact source and distribution channel; floating tags or an unverified pull stop qualification |
| Real local deployment | Dedicated local node and funded wallet, out-of-band genesis pin, one-attempt journal, transaction receipt, independently finalized checkpoint and constructor/verifier-key readback | Operator supplies isolated ledger, wallet custody and genesis approval; simulator or mocked-provider output is not evidence |
| Threshold maintenance | Governance-approved public committee keys, threshold, custody assignments, signed transition plan, submission receipt, finalized readback and adversarial rejection checks | Governance must approve roster/threshold and at least threshold key holders must participate; bootstrap key alone stops release |
| Offline actor journeys | Egress-deny policy and logs covering host, containers, browser and proof server; issuer, verifier, auditor, maintainer, recognition, DID/VC/status and TRQP evidence on the deployed local ledger | Operator supplies local DID/VC/status authority and proof service; fixture-backed status cannot be reported as live verification |
| Restart and recovery | Independent service restarts, ledger/history and key continuity, restore on a second isolated host, stale/conflicting checkpoint rejection and ambiguous-transaction reconciliation | Operator supplies backup custody and an approved recovery decision; resetting to identical genesis without history continuity fails |
| Independent review | Exact-head security review of contracts, adapters, custody, egress, install provenance, and recovery evidence, with disposition of findings | A reviewer independent of implementation and release-owner sign-off are mandatory |

The gates are conjunctive. An unresolved safety finding stays blocking even if
filed as a follow-up. Keep draft promotion PR #198 draft until its scope and
release gates are explicitly updated and independently reviewed. Nothing in
this plan authorizes a public-network release or a Preprod deployment.
