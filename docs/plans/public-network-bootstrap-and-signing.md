# Public-network bootstrap and governance signing (#200)

Status: implementation plan, not a release claim. The 0.1.0 simulator fixture
remains the supported baseline until the tests and network qualification below
pass. This slice is independent of PR #203 and must be rebased after it lands.

Local progress: the pure Compact `deploymentBoundMaintainerActionDigest` and
strict TypeScript sign/verify helpers use a versioned network-and-address-bound
payload. The active governed-action verifier, API prechecks, signers, evidence
readers, demos, and test fixtures use that digest. Replay tests reject the same
signature at another address or network while accepting it at the source.
The remaining release gates are an approved non-conflicted recovery rule and
qualification against a finalized public-network deployment.

Constructor bootstrap is implemented locally: the former `initializeRegistry`
body runs during construction, the public circuit is removed, and simulator
fixtures pass deployment inputs to `initialState`. A hostile-first-caller test
checks that an unregistered caller cannot replace the constructor state. This
still needs real-network qualification before #200 is done.

The constructor also requires a nonzero `deploymentNetworkIdCommitment` and
stores it as sealed ledger state. The integration simulator pins the `undeployed`
identifier used by its DID and epoch fixtures; this does not attest to a deployed
network. Deployment tooling must independently
authenticate the actual network before signers rely on the declared value.
The generated Compact constructor runs under a dummy contract address. Its
initialization event is therefore separately domain-separated and bound to
the pinned network, but **not** to the eventual contract address. Only
post-deployment governed event hashes and action signatures bind
`kernel.self().bytes`. An initialization event alone must never be accepted
as proof of a specific deployment address.

The client now provides `prepareFinalizedDeploymentActionDigest` as a
signer-side preflight. It reads a current finalized action state from an
independently trusted port, compares the selected network, deployed address,
registry commitment, network commitment, active policy, and action sequence,
then returns the same Compact digest used by the contract. It rejects
`undeployed` and placeholder domains. This does **not** supply a network
adapter or establish finality by itself: the port implementation must
authenticate the actual network and finalized ledger state, and the operator
must pin the intended deployment. Mocked-port tests are not public-network
qualification. No network-private signing key is handled by this helper.

The integration package now provides `createCheckpointedDeploymentActionReader`.
It accepts a Midnight `PublicDataProvider` and a separate trusted checkpoint
source, queries the contract state **at the checkpoint block hash**, decodes
the generated Trust Registry ledger, and supplies the registry/network/policy/
sequence fields to the signer preflight. The checkpoint source must establish
both the named network and block finality independently of the indexed
evidence being evaluated. The simulator test exercises the real ledger decoder
and block-hash query shape, but not an actual network or a trusted checkpoint
implementation. A public-network qualification still needs a target network,
funded deployment wallet, authenticated checkpoint source, deployment receipt,
and finalized readback of the deployed address and constructor state.

`createRpcFinalizedCheckpointSource` can supply that reader's checkpoint from a
Midnight node RPC. It checks `chain_getBlockHash(0)` against a separately
approved genesis hash **before** accepting `chain_getFinalizedHead`; it never
learns the trusted pin from the same endpoint. The node RPC and indexer are
distinct data sources, but the node itself remains a trusted finality source.
The operator must provision the approved network/genesis pair and an HTTPS
endpoint, then compare the resulting block hash with the indexer's
block-hash-scoped contract state. A successful RPC test does not prove contract
deployment, wallet funding, or constructor state. The source rejects remote
plain HTTP, URL-embedded basic credentials, malformed JSON-RPC responses,
zero hashes, and wrong genesis. Project tokens in query parameters are not
logged by this library and must still be handled as secrets by the host.

`createPublicNetworkDeploymentActionReader` composes this pinned RPC source
with Midnight's published 4.1.1 indexer public-data provider. The operator
supplies HTTPS indexer query and WSS subscription URLs; remote plaintext and
URL-embedded credentials are rejected. The indexer state is read at the
node's finalized block hash, not at the indexer's latest head. This is a
read-only provider assembly, not a deployment receipt or independent proof
that the node is honest. The genesis pin must still come from an approved
source outside the configured RPC/indexer pair.
The `trust-registry inspect-deployment` CLI exposes this read as JSON, including
the exact finalized block hash used for the ledger query. It accepts no
wallet key and performs no mutation. Its output is inspection evidence, not
a public-network deployment or recovery qualification result.

`deployPublicTrustRegistry` is a host-invoked deployment adapter, not a
default CLI command. The host supplies its own funded Midnight.js
`ContractProviders`, an explicit contract-maintenance `SigningKey`, network
ID (`preview`, `preprod`, or `mainnet`), RPC/indexer endpoints, and an
independently approved genesis pin. The adapter checks the SDK network setting,
the pinned node checkpoint, indexer URL policy, and nonzero constructor
commitments before invoking the published Midnight deployment API. The
maintenance key authorizes Midnight contract maintenance; it is **not** a
Trust Registry governance quorum key. The adapter never returns private
deployment transaction data or manages wallet/key custody.

The returned public receipt is retained even if the finalized readback is
`pending` (indexer lag), `unavailable` (read error), or `mismatch` (observed
ledger disagrees). Only `verified` means the observed registry ID, deployment
network commitment, active policy, and initialization action count of one
match the supplied constructor inputs at a pinned finalized block. A non-
verified result must be investigated with read-only inspection using the
receipt, **not** retried as a fresh deployment. This is still not public-
network qualification: no funded deployment was performed, the host providers
and RPC/indexer are trusted, and a readback from one indexer is not a
cryptographic proof of canonical state. Issue #200 remains open until an
operator-approved live deployment and independent finality/replay checks.

As of October 2026, [Midnight's environment reference](https://docs.midnight.network/relnotes/network)
lists public Preview RPC/indexer endpoints. The old Midnight-hosted Preprod
RPC/indexer endpoints were retired on 9 October; Preprod now uses Blockfrost
endpoints and a Midnight Preprod project token. Do not copy stale Preprod URLs
from older DID examples. The [deployment guide](https://docs.midnight.network/guides/deploy-and-operate)
describes provider construction and a funded wallet; those pieces are still
required for #200's live deployment qualification.

## Threats and invariants

1. A third party must not be able to call an uninitialized deployed contract
   first and choose its registry identity, policy, or bootstrap maintainer.
2. A governed action signed for one deployed contract must fail against a
   different contract, even if its registry ID, policy, keys, and sequence match.
3. A governed action signed for one named Midnight network must fail against
   another named network. The contract must not treat a caller-provided network
   label as an independently authenticated chain identity.
4. An accepted threshold policy must leave a non-conflicted quorum for each
   action it purports to authorize. A policy allowing an all-member emergency
   or archival threshold while excluding the target from its own removal can
   strand the registry; the recovery rule needs explicit governance approval.
5. Every signer, simulator, operator surface, event consumer, and published
   evidence format must use the same versioned transcript. No contract-only
   digest change is acceptable.

## Supported toolchain findings

- Compact 0.31.1 supports constructor arguments and constructor-set ledger
  state. Constructor initialization can remove the public first-call window.
- `kernel.self().bytes` is used elsewhere in this repository to bind a VC
  authority domain to the deployed contract address. The simulator must hold a
  stable address for its lifetime. The Compact runtime uses
  `dummyContractAddress()` while executing the constructor, so constructor
  evidence cannot claim address binding.
- No contract-observable network or genesis identifier has yet been found in
  the supported Compact API. A constructor-pinned `networkIdCommitment` can
  separate honest deployments only if deployment tooling and signers verify
  that the pinned value matches the actual target network. It must not be
  described as an on-chain proof of chain identity.
- The VC status-registry ADR-0011 independently prohibits unauthenticated
  first-caller initialization and requires network/deployment-bound mutation
  authority. Its topology and issuer ownership rules do not transfer directly
  to the Trust Registry.

References:

- [Midnight private contract guide](https://docs.midnight.network/guides/build-a-private-smart-contract)
- [Midnight deployment guide](https://docs.midnight.network/guides/deploy-and-operate)
- `midnight-verifiable-credentials/docs/decisions/0011-status-registry-namespace-and-authority.md`
- `docs/decisions/trust-registry-knowledge-base.md` (VC authority domain and
  stable simulator address findings)

## Bounded implementation order

1. Specify a versioned deployment domain: explicit network identifier,
   `kernel.self().bytes`, registry ID, and a deployment-unique value if address
   uniqueness across networks cannot be guaranteed by the target ledger.
   Define the exact byte encoding, domain separator, and how a signer obtains
   authenticated deployment/network facts. Reject unknown networks and zero
   or placeholder domains.
2. Move registry identity, policy, and bootstrap maintainer installation into
   the constructor or an equivalently authenticated atomic deployment path.
   Remove the public `initializeRegistry` circuit. Preserve one canonical
   initialization event at governance action count one. Update generated
   bindings and simulator fixtures together.
3. Bind all governed action digests to the pinned deployment domain. Update
   the Compact verifier and TypeScript signing helpers atomically, then the
   simulator, CLI, API action preparation, demos, epoch evidence, TRQP exports,
   and historical event verification. Do not leave a permissive old digest or
   compatibility fallback in this unreleased repository.
4. Add cross-deployment, wrong-network, stale-policy, stale-sequence, and
   forged-bootstrap negative tests. Include a case where a hostile caller
   invokes every exported circuit before the authorized deployer; none may
   install a different root. Prove accepted actions still require distinct,
   active registered signers.
5. Decide the non-conflicted recovery policy explicitly. Either reject a
   threshold revision that strands removal or define a separate recovery
   authorization with a tested trust boundary. Test 2-of-2 and 3-of-3 cases,
   including subject exclusion and emergency/archival action families.
6. Run light, full Compact, integration, and demo validations. Qualify the
   actual supported network deployment path with finalized state reads before
   closing #200 or calling 0.1.0 public-network ready. Update the spec, ADR,
   operator deployment/key-management guide, and release checklist.

## Stop conditions

- If the 0.31.1 runtime cannot bind the actual contract address during proof
  verification, stop rather than accepting a caller-supplied address.
- If the target network cannot provide an authenticated network identity to
  the signer/deployer, document the remaining cross-network assumption and
  keep the public-network release gate closed.
- If network tests use only a simulator or unchecked provider response, do not
  mark the network qualification complete.
