# Ledger 9 local development

This describes the **shared Ledger 9 development chain**, not the historical
Ledger 8 `0.1.0` standalone release. Keep three evidence levels separate:

| Path | What a pass proves | What it does not prove |
| --- | --- | --- |
| Guided role demo | Browser navigation, requests, and practice votes work with fixtures. | An on-chain grant or signed committee. |
| Shared-chain contract smoke | A source-matched Compact action proved, finalized, and was read back. | Accepted DID/VP evidence or a qualified actor journey. |
| Live actor qualification | DID session, accepted VP and status, governed action, epoch, and exact readback all share one approved deployment. | **Not yet run.** |

The shared chain belongs to its designated owner and may contain other users'
transactions. Attach to it; do not start, restart, reset, or remove its Docker
project or volumes. Restart, restore, and deliberately ambiguous submission
tests need a separately owned isolated project.

## Attach without starting services

Use Node.js 24 and the repository's pinned pnpm. In a source checkout with
dependencies installed, run:

```sh
pnpm run localnet:discover
```

This read-only discovery expects node `127.0.0.1:9944`, indexer GraphQL API
v4 `127.0.0.1:8088/api/v4/graphql`, and proof server `127.0.0.1:6300`.
It checks versions, node/indexer genesis and indexed progress, and never
invokes Docker. On failure, keep the diagnostic and ask the stack owner.

For a specific deployment, additionally pin the observed genesis and a
**non-genesis** block height/hash in a private ignored environment file using
`TR_EXPECTED_GENESIS_HASH`, `TR_EXPECTED_CHECKPOINT_HEIGHT`, and
`TR_EXPECTED_CHECKPOINT_HASH`. Genesis alone cannot detect a replacement
development chain. Keep wallet seeds, journals, approvals, and the pin out of
Git and screenshots. With the private pin in this checkout, run:

```sh
node --env-file=artifacts/ledger9-current-chain.env scripts/check-ledger9-local-stack.mjs
```

That file is local evidence, not a repository fixture. Prepare your own pin
for your chain; do not copy another session's checkpoint or deployment
journal. An advancing head is normal, but changed genesis, pinned block,
contract, or source image stops the run.

## Inspect finalized contract state

Take the contract address from your deployment journal and the manifest from
its verified source-matched installation. Set `CONTRACT_ADDRESS` and
`SOURCE_MANIFEST` to those independently reviewed values, then run:

```sh
node --env-file=artifacts/ledger9-current-chain.env scripts/read-ledger9-registry.mjs \
  --address "$CONTRACT_ADDRESS" \
  --manifest "$SOURCE_MANIFEST"
```

Add `--issuer-label "$ISSUER_LABEL"` to inspect an exact issuer. Compare the
reported genesis, contract, finalized block, verifier-key catalog, governance
sequence, role status, and lifecycle event root with the one-shot submission
receipt. A numeric key count or API health response is not source or finality
evidence. Preserve the private plan, source SHA, manifest, chain pin, proof,
reservation, transaction, and independent readback together.

As of 18 November 2026, one **fixture-labeled** issuer in the policy-bound
development registry passed proposal, two-maintainer authorization, and
activation. Readback found governance sequence 13, one active issuer, 66
source-matched keys, and zero published epochs. Its proposal used a raw schema
label and placeholder status-policy commitment, not an accepted VP and
canonical issuer resource/status binding. It is not a trusted issuer and
cannot support an authentic authorization evidence bundle. Exact private
trial receipts are documented in `docs/plans/ledger9-migration.md` in the
source checkout.

## Try the UI separately

The [guided demo](quickstart.md#first-time-role-demo) serves a browser and
file-backed API on loopback; it does **not** query this deployed contract.
Persona votes are browser-local practice state, not maintainer signatures.
The [E2E test guide](end-to-end-testing.md) has headless and Playwright
fixture commands. Label their reports `fixture`; do not combine a demo
screenshot and a shared-chain transaction into one claimed actor journey.

## Live actor qualification still needed

The API's opt-in `createBoundLocalIssuerProposalPort` requires a deployment-
specific, independently reviewed adapter for accepted VP admission, DID and
VC-status verification, trusted time, authenticated finalized readback,
immutable source-matched provider code, signed writer approval, and a
one-shot journal. The packaged read-only CLI and demo do not supply it. DID
sign-in proves identity only; VP eligibility and governed authorization are
separate.

A complete live run must capture, under one genesis/source/contract pin: DID
challenge and session, pending application, accepted VP and live status with
canonical target, signed maintainer proposal and decision, finalized
activation, a defensible authorization statement and inclusion root, epoch
publication, and exact-ID readback. If an input is missing or fixture-supplied,
mark the case `not run` even if a Compact circuit succeeds. See the
[actor host handoff](standalone-actor-host.md) and [status](status.md) pages.
