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

The staged install directory must contain `install-inventory.json`, the
release-candidate package manifest and its ten tarballs, separate OCI image
archives for node, indexer, and proof server, and the proof server's verified
Ledger 8 public-parameter cache. Use this shape, replacing every
placeholder with approved exact values:

```json
{
  "format": "tr-standalone-install-v2",
  "sourceRevision": "<40-character signed source SHA>",
  "packageManifest": "release-candidate-manifest.json",
  "artifactDirectory": "artifacts/npm",
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
The builder creates a **new** ignored `artifacts/standalone-install/<source SHA>/`
directory; it does not overwrite an existing bundle or rebuild Compact keys.
It packs ten packages, copies the 18 local proof-parameter files, exports the
three digest-pinned Compose images, writes the release and install manifests,
and runs the read-only bundle verifier. Retain the resulting directory and
hashes as candidate bytes for operator approval. If the command fails, the
partial directory is retained for inspection; use a new signed source commit
or a separately reviewed recovery procedure rather than silently replacing
candidate bytes.

Run `node scripts/check-standalone-install.mjs <bundle-directory>` before
disconnecting and after transfer. It verifies the package manifest against
the packed contract and hashes each image archive and all 18 required proof
parameter files without network access. A missing, extra, linked, or altered
parameter file fails the check. The proof server verifies downloaded parameter
contents during online installation; keep the checked cache as a read-only
runtime input, not as an unpinned writable container layer.
The verifier also checks each tagless OCI archive's internal manifest digest
against the approved image reference and its arm64 config bytes. It does not
establish who approved the reference or prove origin from the registry;
record independent registry-digest verification at acquisition.

On a clean offline host, run
`node scripts/load-standalone-install-images.mjs <verified-bundle-directory>`.
It rechecks the bundle, loads archives without pulling, verifies each Docker
image ID against the archived config bytes, and creates source-SHA-scoped
local tags. Reject a tag already bound to different bytes. Set
`TR_NODE_IMAGE`, `TR_INDEXER_IMAGE`, and `TR_PROOF_SERVER_IMAGE` to the returned
tags. Then use both `deploy/standalone/compose.yml` and
`deploy/standalone/compose.offline.yml` with `docker compose -f
deploy/standalone/compose.yml -f deploy/standalone/compose.offline.yml up
--pull never -d --wait`; the overlay sets `pull_policy: never` for every image. Do this
on a separate clean host or daemon and capture load output, image IDs, restart
logs, and denied-egress evidence. A load against this development host, where
the upstream images are already present, does **not** prove clean offline
installation. Include pinned runtime,
browser, DID/VC/status, Compose, and toolchain dependencies in the operator
install record; this three-image inventory alone is not a complete install or
qualification result.

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

### First-run setup wizard (initial slice)

The local CLI wraps the existing install verifier, genesis preflight, and
one-attempt deployment entry point. Create a **new private directory** for
each installation; do not reuse a prior attempt's directory:

```sh
node scripts/standalone-setup-wizard.mjs run /absolute/private/setup-directory
# Or run each step separately for an auditable operator session:
node scripts/standalone-setup-wizard.mjs init /absolute/private/setup-directory /absolute/verified-install-bundle
node scripts/standalone-setup-wizard.mjs observe /absolute/private/setup-directory /absolute/approved-genesis-pin.json
node scripts/standalone-setup-wizard.mjs deploy /absolute/private/setup-directory /absolute/approved-deployment-plan.json
node scripts/standalone-setup-wizard.mjs status /absolute/private/setup-directory
```

The wizard verifies staged bytes, checks that the pin and deployment plan
match the installed source and observed genesis, and saves a mode-0600 setup
record in a mode-0700 directory. It reserves a deployment attempt **before**
calling the provider. If the process exits, the provider fails, or the receipt
is unclear, do not invoke `deploy` again against that setup; inspect the
deployment journal and finalized chain, then obtain a human recovery decision.
The wizard does not generate or approve a genesis hash, provider module,
funded wallet, committee roster, threshold, or key custody. A public local
genesis wallet and 1-of-3 committee are permitted only for a development
smoke, never as RC approval. Independent genesis and final committee approvals
must be collected during first setup from the responsible humans, not inferred
from the node's own response or a typed acknowledgement. Later wizard slices
must bind those approvals to the evidence record and execute finalized
maintenance readback, offline actor journeys, and recovery qualification.
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
one container to the internal ledger network. The relay has no configurable
upstream destinations. Its host ports are published on `127.0.0.1` only;
`30944` forwards node RPC, `38088` forwards the indexer, and `36300` forwards
the proof server. Use those host ports in the operator's approved endpoint
plan and separately pin the opaque wallet provider endpoints. Stop and remove
the relay before the offline runtime test; the relay has a `bridge` attachment
and is **not** evidence of egress denial.

```sh
docker run -d --name tr-standalone-install-relay --network bridge \
  --publish 127.0.0.1:30944:30944 \
  --publish 127.0.0.1:38088:38088 \
  --publish 127.0.0.1:36300:36300 \
  --mount type=bind,src="$PWD/deploy/standalone/local-install-relay.py",dst=/relay.py,readonly \
  --entrypoint /usr/bin/python3 \
  midnightntwrk/midnight-node@sha256:c3e46f8beff308b352813cd8904f6480c331504e09060abd671b8a32e1255220 \
  /relay.py
docker network connect tr-standalone-local-smoke_ledger tr-standalone-install-relay
# Perform approved installation/deployment checks, then remove the access path.
docker stop tr-standalone-install-relay
docker rm tr-standalone-install-relay
node scripts/check-standalone-topology.mjs
```

The observed host checks returned the pinned genesis from `127.0.0.1:30944`,
GraphQL `Query` from `127.0.0.1:38088/api/v4/graphql`, and proof-server
version `8.1.0` from `127.0.0.1:36300/version`. These establish connectivity
only. Do not leave the relay running during egress-denied actor journeys.

Run `node scripts/check-standalone-topology.mjs` against the dedicated
`tr-standalone-local-smoke` project after the offline cold start. It reads
Docker metadata without changing containers or volumes and fails on extra
network attachments, missing persistence mounts, a writable proof cache,
fetch-enabled proof server, or non-digest-pinned images. Its JSON deliberately
reports `egressDenied: "not-verified"` and `actorJourneys: "not-run"`: an
internal bridge is a useful precondition, not proof of denied external DNS or
egress for the wallet, API, browser, and backup processes. Capture firewall
logs and run real actor journeys under the release egress policy separately.

The current API's file-backed
simulator mode may be used for demonstrations, but must be labeled fixture-only.
The genesis pin alone may not distinguish a fresh local node from one reset
to the same chain specification: persist and verify chain state, receipts,
and finalized history across restarts. A node without a progressing finalized
head yields `pending`, not qualification evidence.

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
