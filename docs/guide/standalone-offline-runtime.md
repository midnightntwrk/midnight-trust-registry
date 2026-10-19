# Standalone Offline Runtime Qualification

Status: qualification plan, not a claim that the full stack is deployed or
supported offline. Online access is allowed during installation; after setup,
the running Trust Registry must not depend on public network services.

This profile is separate from Preprod qualification. A local Compact simulator
and loopback HTTP actor journey are useful development evidence, but are not a
deployed standalone Midnight ledger or a substitute for public-network
finality. Offline operation also does not make a local node or status authority
trustworthy by itself.

## Install While Online

1. Pin a reviewed version of
   [midnight-local-dev](https://github.com/midnightntwrk/midnight-local-dev)
   and its node, indexer, and proof-server image digests. Install Node.js,
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

## Offline Runtime Boundary

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

The official [Midnight local-dev project](https://github.com/midnightntwrk/midnight-local-dev)
documents its container startup and funding flow. Its development genesis
wallet and mnemonic examples are not production secrets or public-network
security guidance.
