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
It checks versions, node/indexer genesis and indexed progress, and requires the
indexed block to be no later than the node-reported finalized head. It never
invokes Docker. This checks consistency with the attached node, not independent
finality or registry authorization. On failure, keep the diagnostic and ask the
stack owner.

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
The readback reader rechecks the private genesis and non-genesis checkpoint
against the node before each finalized-state query; discovery alone is not a
durable chain-identity check. The node remains a trusted local input, not an
independent cryptographic finality proof.

For a development checkout that retains full generated Compact artifacts but
has no Linux release manifest, build a source-bound keyless candidate from
those artifacts with the exact signed source SHA and pinned Compact 0.36.0
`zkir-v3` binary. Use a new, empty destination for each source revision:

```sh
node scripts/keyless-zkir-bundle.mjs create \
  contracts/trust-registry/src/managed/trust-registry \
  "$KEYLESS_DIR" "$SIGNED_SOURCE_SHA" "$ZKIR_BIN"
```

Record the resulting manifest digest separately, then read the same finalized contract
with `--keyless-dir`, `--keyless-manifest-sha256`, and
`--expect-source-revision` in place of `--manifest`:

```sh
node --env-file=artifacts/ledger9-current-chain.env scripts/read-ledger9-registry.mjs \
  --address "$CONTRACT_ADDRESS" \
  --keyless-dir "$KEYLESS_DIR" \
  --keyless-manifest-sha256 "$KEYLESS_MANIFEST_SHA256" \
  --expect-source-revision "$SIGNED_SOURCE_SHA" \
  --issuer-label "$ISSUER_LABEL"
```

This rechecks the candidate against retained full outputs and compares all
finalized verifier-key hashes. Its `local-keyless-candidate` result has
`releaseQualified: false`: it does not authenticate the Git history, approve
the deployment, or establish actor evidence. See the dated observation in
[#321](https://github.com/midnightntwrk/midnight-trust-registry/issues/321)
rather than treating one shared-chain snapshot as permanent setup data. A
fixture-labeled active record whose `epochEventRootMatchesLifecycle` is false
cannot support an epoch-backed authorization claim.

On a clean host without the full prover-key tree, add
`--keyless-generator "$ZKIR_BIN" --keyless-generator-sha256 "$ZKIR_BIN_SHA256"`
to the same readback command. The binary digest must come from an independently
trusted input. This mode regenerates and compares each binary ZKIR and key pair
one circuit at a time, removes its temporary keys, then checks the finalized
verifier catalog. It can take several minutes for all circuits. The output
reports `keylessVerification: "streamed-keygen"` instead of `"full-output"`;
neither mode qualifies a Linux release bundle or live actor journey.

## Try the UI separately

The [guided demo](quickstart.md#first-time-role-demo) serves a browser at
`http://127.0.0.1:4273/demo.html?apiBase=http%3A%2F%2F127.0.0.1%3A4500`
and a file-backed API on loopback; it does **not** query this deployed contract.
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
