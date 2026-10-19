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
deployment adapter must authenticate the local network genesis, deploy the
compiled contract, persist its receipt, and read back the finalized contract
image. The current public adapter rejects `undeployed` and remote plaintext
endpoints by design; do not bypass it by relabeling the local network as
Preprod. A separate reviewed local adapter and provider configuration are
still required. The current API's file-backed simulator mode may be used for
demonstrations, but must be labeled fixture-only.

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
