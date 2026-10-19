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
release-candidate package manifest and its ten tarballs, and separate OCI image
archives for node, indexer, and proof server. Use this shape, replacing every
placeholder with approved exact values:

```json
{
  "format": "tr-standalone-install-v1",
  "sourceRevision": "<40-character signed source SHA>",
  "packageManifest": "release-candidate-manifest.json",
  "artifactDirectory": "artifacts/npm",
  "images": [
    { "role": "node", "reference": "registry.example/node@sha256:<digest>", "archive": "images/node.tar", "archiveSha256": "<archive sha256>" },
    { "role": "indexer", "reference": "registry.example/indexer@sha256:<digest>", "archive": "images/indexer.tar", "archiveSha256": "<archive sha256>" },
    { "role": "proof-server", "reference": "registry.example/proof-server@sha256:<digest>", "archive": "images/proof-server.tar", "archiveSha256": "<archive sha256>" }
  ]
}
```

Run `node scripts/check-standalone-install.mjs <bundle-directory>` before
disconnecting and after transfer. It verifies the package manifest against
the packed contract and hashes each image archive without network access.
The image reference is an operator-approved pin; archive hashing alone cannot
prove that the archive came from that registry digest. Record independent
registry-digest verification at acquisition, and prove `docker load` plus
restart from those bytes with image pulls disabled. Include pinned runtime,
browser, DID/VC/status, Compose, and toolchain dependencies in the operator
install record; this three-image inventory alone is not a complete install or
qualification result.

## Offline Runtime Boundary

The repository includes `deploy/standalone/compose.yml` as an **isolated
development smoke stack**, derived from a pinned `midnight-examples` revision.
It uses arm64 image digests, separate `tr-standalone-local-smoke` volumes, an
internal container network, and loopback ports 29944 (node), 28088 (indexer),
and 26300 (proof server). Provision `TR_INDEXER_PASSWORD` and
`TR_INDEXER_SECRET` in a private, untracked environment file before running
`docker compose --env-file <private-env-file> -f deploy/standalone/compose.yml
up -d --wait`. Never run `down -v` against a ledger whose history is evidence.
The image digests identify upstream bytes, not an approved distribution
channel. This Compose file does not start the Trust Registry API, portals,
wallet, DID/VC/status authority, or egress-denial harness and does not close
any release gate by itself. Validate that `/data` actually retains node and
indexer state before using the volumes for restart/restore evidence.

The local Midnight network uses network ID `undeployed`, not `preprod`. The
upstream local-dev stack exposes node RPC, indexer, and proof-server services
on loopback by default. Bind them to an isolated network, not public
interfaces. Start and fund local accounts before disabling egress. A local
proof server sees witness data and must remain inside the same trust boundary.

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
reserves one attempt before the SDK call and retains the public receipt if the
adapter returns. A missing receipt after reservation means an unknown outcome,
not permission to redeploy; inspect the original intent and finalized local
chain state before a human recovery decision. These helpers do not install or
run a local node, prove egress denial, or demonstrate a live maintenance
transaction. The initial
single-key authority remains unsafe for release until a separately approved
committee is observed after finality. Durably record the deployment receipt,
committee approval, and journal before claiming a supported local deployment.
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
