# Preprod Trust Registry Qualification For Administrators

Status: operator runbook draft. No Preprod deployment or threshold-authority
transition has been executed. This is not release approval.

The selected first public qualification target is **Preprod**. The approved
maintenance model is a threshold committee aligned with Trust Registry
governance. The administrator executes the deployment and transition; an
independent reviewer approves the pins and reads the finalized result.

## Inputs To Approve Before Deployment

Record these in an access-controlled change request, not in this repository:

1. The exact signed/DCO source SHA, V2 release manifest SHA-256, ten package
   hashes, and complete per-circuit verifier-key hash catalog. Run full
   integration, package-content, pack, manifest, and clean-consumer checks at
   that same source revision.
2. The Preprod network ID and genesis hash from an independently approved
   source. Do not derive the trusted genesis pin from the RPC or indexer used
   for deployment. Record the provider service identity, endpoint URLs with
   tokens redacted, and a separately operated finality checkpoint source.
3. The registry ID, DID and policy commitments, bootstrap maintainer identity,
   key ID and public key, and intended governance expansion to at least three
   distinct active maintainers with a threshold of at least two.
4. At least three distinct, canonical maintenance public verifying keys and an
   approved threshold of at least two. Record custodian assignments, custody
   and recovery procedure, signer separation, and evidence that this committee
   is aligned with the governance policy. The example minimum is not approval
   of a particular roster or threshold.
5. A funded Preprod wallet, locally operated proof server, encrypted private
   state store, and a temporary contract-maintenance signing key. Keep wallet
   and maintenance private keys out of logs, tickets, manifests, and PRs.

Use the current [Midnight environment reference](https://docs.midnight.network/relnotes/network)
for Preprod endpoint shapes. The old Midnight-hosted Preprod RPC/indexer URLs
were retired; Blockfrost endpoints require a Preprod project token. The
[deployment guide](https://docs.midnight.network/guides/deploy-and-operate)
describes provider construction and wallet funding. Never commit the token or
include it in diagnostic output.

## Deployment And Readback

1. Set Midnight.js network ID to `preprod` before constructing providers.
   Authenticate the pinned node's genesis and finalized head independently of
   the indexer. Stop on any network, genesis, TLS, or finality mismatch.
2. Supply the approved bootstrap inputs, full release manifest, funded
   providers, and temporary maintenance signing key to the host-invoked
   `deployPublicTrustRegistry` adapter. There is deliberately no default
   wallet-handling CLI. Record the public transaction ID, block hash, height,
   and contract address immediately; redact private transaction and provider
   data.
3. Read the deployed image at a finalized block hash. A matching bootstrap
   result is intentionally `unsafe-maintenance-authority`, because the SDK
   initially installs one key. `pending`, `unavailable`, `invalid-image`, and
   `mismatch` are stop/investigation states, not permission to redeploy. Do
   not create a second contract merely because the indexer lags.
4. Independently compare the registry identity, constructor commitments,
   operation catalog, every verifier-key hash, bootstrap maintainer, and
   single-key maintenance authority with the approved manifest and receipt.

## Committee Transition Gate

**Do not call Midnight.js 4.1.1 `replaceAuthority` for this transition.** Its
published high-level API accepts one `SigningKey` and produces another
single-key authority. The lower-level Ledger 8 `MaintenanceUpdate` and
`ReplaceAuthority` types can represent a committee, but this repository does
not yet provide a reviewed transaction builder, submission/recovery workflow,
or adversarial tests for that path. The administrator must not substitute a
manual unreviewed transaction. Issue #213 remains a security/release blocker.

Before executing a future reviewed transition, expand the Trust Registry
governance roster to at least three active maintainers under signed governance
actions, set its approved multi-party threshold, and independently verify the
finalized governance state. The transition must be bound to the exact contract
address and current maintenance counter, increment that counter exactly once,
use the approved distinct public keys and threshold, and be authorized by the
current maintenance authority. The host must preserve the transaction receipt
across crashes and never blindly retry an ambiguous submission.

After the transition finalizes, invoke `readPostDeploymentPublicTrustRegistry`
with the original receipt, approved governance pin, committee keys and
threshold, and exact release manifest. Only `verified` after independent
finalized readback of the authority, governance, and all verifier-key hashes
can satisfy the image check. It is not by itself a proof that the network
provider is honest. Keep #200 and #213 open until the real deployment,
transition, independent readback, adverse cases, and recovery decision are
reviewed. Do not merge draft promotion #198 on this runbook alone.

## Evidence To Retain

- Approved source and manifest hashes, network/genesis pin provenance, and
  committee policy approval without private keys or project tokens.
- Funding and provider readiness checks, deployment receipt, finalized
  checkpoint hash, bootstrap image comparison, governance expansion receipts,
  maintenance transition receipt, and post-transition image comparison.
- Independent reviewer sign-off, wrong-genesis/wrong-authority/replay tests,
  incident and recovery decision, and exact-head CI results.
