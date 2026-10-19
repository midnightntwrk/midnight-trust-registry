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
single-key authority. `preparePublicNetworkCommitteeTransition` now reads a
genesis-pinned finalized deployment image, checks its identity, governance,
verifier keys, and initial maintenance authority, and builds a short-lived
Ledger 8 `ReplaceAuthority` transaction for the approved committee. It returns
the exact `dataToSign` and a public summary for external custodian review.
The bootstrap custodian signs only those bytes; `authorize(signature)` verifies
that signature and returns an unproven transaction without handling the
private key. Unit tests exercise the Ledger 8 update and rejection cases.

`submitPublicNetworkCommitteeTransition` re-reads the pinned finalized image,
verifies the external signature, and uses `submitTxAsync` through a
`FileMaintenanceTransitionJournal`. Give that journal one stable path per
deployment, inside a pre-provisioned, private (0700), locally owned directory
on single-host storage. The adapter will not create that directory. It
reserves the attempt before
the SDK proves, balances, or broadcasts; an error or restart leaves the
reservation in place and **never retries automatically**. If the SDK returns
a transaction ID, the adapter attempts to retain it in a separate durable
record; if that write fails, the thrown error carries the returned ID, but a
process crash at that point can still lose it. The reservation retains the
intent expiry and reservation time. Every SDK failure, including proving or
balancing failures, requires read-only reconciliation of the journal and
independently finalized network state before any operator-approved new
attempt. Do not delete or rotate the journal merely to bypass the reservation.

This is **not yet a completed production recovery workflow**. The custodian
and host must durably retain the approved plan, signature provenance, receipt,
and recovery decision, and must independently verify finality and post-update
authority before considering the transition complete. The file journal does
not coordinate multiple hosts or prove that a transaction finalized. Never
sign opaque bytes without showing the network, contract address, finalized
block, current and next counters, committee keys, and threshold. Independent
human security review and a real Preprod transaction are still required;
#213 remains a security/release blocker.

Before executing a reviewed transition, expand the Trust Registry
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
