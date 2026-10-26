# Self-hosted standalone: first operator run

The first 0.1.0 release candidate targets a **local Midnight ledger with an
offline runtime**. Installation may use the network. Preview, Preprod, Mainnet,
and Kubernetes are not part of this qualification. Start with a dedicated
Docker project; never reuse another project's node, volumes, or wallet.

::: warning Evidence boundary
The commands below produce install and **pre-deployment ledger-bridge smoke**
evidence. They do not deploy the Trust Registry, authorize a maintainer, or
complete an end-to-end actor journey. The local API image is read-only until a
reviewed governed-write adapter exists. A simulator test, HTTP response, or
node-reported genesis hash cannot replace finalized contract readback.
:::

## Choose the right test

| Run | What it can establish | What it cannot establish |
| --- | --- | --- |
| `./run.sh --light` | Source, Compact, package, and simulator regression checks | A deployed local ledger |
| `pnpm run test:standalone-topology` | Topology and observer behavior with injected fixtures | A running offline stack |
| Verified bundle + wizard `observe-stack` | Pinned images on an isolated bridge; canary DNS/HTTPS denial | Genesis approval, deployed contract, actor or host egress |
| Restart observer | Continuity of a self-attested local finalized checkpoint across service restart | Authenticated finality, backup restore, actor actions |
| Operator acceptance cases `L01`-`S01` | The required evidence inventory for one reviewed candidate | Automatic verification of the truth of every case |

Use `./run.sh --light` only in a disposable checkout: it can remove full
generated Compact artifacts. Preserve the exact-source signed install bundle,
proof parameters, generated keys, and private approval evidence.

## Bring up the ledger bridge

1. While online, select a bundle **derived from an approved GPG-signed source
   commit** containing the release manifest, ten packages, six pinned images,
   and proof parameters. Independently authenticate the source commit and
   compare the bundle inventory SHA-256 with an approved digest received
   through a separate channel. `check-standalone-install.mjs` verifies the
   bundle's internal bytes, **not its provenance**. Record the source SHA,
   signer fingerprint, and inventory SHA-256. A missing independent approval,
   mismatched digest, or bundle from another source revision is a stop condition.
2. Choose a nonexistent setup path under an existing private parent directory,
   unused loopback ports, and a unique `tr-standalone-local-*` Docker project.
   The wizard creates the mode-0700 setup directory. Run `init` and
   `prepare-stack` as shown below. Review the resulting Compose configuration
   and private `stack.env`; do not publish its indexer credentials.
3. Load the six archives without pulling, set the three local image tags
   reported by the loader, then start **only** the ledger bridge. The API and
   portals must not start before the human approvals and signed API plan.

```sh
SOURCE_SHA=replace-with-approved-40-character-commit
INSTALL=/absolute/verified/standalone-install/$SOURCE_SHA
SETUP=/absolute/private/standalone-setup
PROJECT=tr-standalone-local-my-run
git verify-commit "$SOURCE_SHA"
shasum -a 256 "$INSTALL/install-inventory.json"
# Compare the signer fingerprint and inventory digest with independently
# approved values before continuing. The checker alone cannot do that.
node scripts/check-standalone-install.mjs "$INSTALL"
node scripts/standalone-setup-wizard.mjs init "$SETUP" "$INSTALL"
node scripts/standalone-setup-wizard.mjs prepare-stack "$SETUP" "$PROJECT" 39944 38088 36300
node scripts/load-standalone-install-images.mjs "$INSTALL"

# Copy the exact node, indexer, and proof-server tags returned by the loader.
export TR_NODE_IMAGE=tr-standalone/node:sha-SOURCE_SHA
export TR_INDEXER_IMAGE=tr-standalone/indexer:sha-SOURCE_SHA
export TR_PROOF_SERVER_IMAGE=tr-standalone/proof-server:sha-SOURCE_SHA
docker compose --env-file "$SETUP/stack.env" -p "$PROJECT" \
  -f "$INSTALL/compose.yml" -f "$INSTALL/compose.offline.yml" config -q
docker compose --env-file "$SETUP/stack.env" -p "$PROJECT" \
  -f "$INSTALL/compose.yml" -f "$INSTALL/compose.offline.yml" up --pull never -d --wait
node scripts/standalone-setup-wizard.mjs observe-stack "$SETUP"
node scripts/standalone-setup-wizard.mjs collect-genesis-candidate "$SETUP"
node scripts/standalone-setup-wizard.mjs status "$SETUP"
```

The candidate file is explicitly **untrusted**. Compare its hash to an
independently reviewed chain specification. The human reviewer, not the
installer or an AI agent, signs the exact genesis approval bytes with their
own GPG key. A ticket ID is optional; the reviewed chain-spec digest is not.
Likewise, governance must approve real maintenance public keys, threshold,
and custody roles. A 1-of-3 development smoke roster is not release approval.

To prepare a private review packet, follow the
[verified temporary relay procedure](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-offline-runtime.md#first-run-setup-wizard-initial-slice),
run `node scripts/standalone-setup-wizard.mjs draft-genesis-pin "$SETUP"`
while that relay is attached, then stop and remove it. Finally run
`pnpm prepare:standalone-genesis-review "$SETUP"`. The packet lists pinned
bytes and the node's untrusted report; it cannot supply an independent chain
specification or a signature.

For pre-deployment continuity, capture a baseline, restart the three dedicated
services without deleting volumes, and verify the prior checkpoint remains
readable at a later height. Retain the raw output in the private setup
directory. This is **not** a backup/restore or authenticated-finality test.

```sh
node scripts/check-standalone-restart.mjs capture "$SETUP"
docker compose --env-file "$SETUP/stack.env" -p "$PROJECT" \
  -f "$INSTALL/compose.yml" -f "$INSTALL/compose.offline.yml" restart
# Restart returns before health and finality advance. Wait for all three
# services to become healthy, then confirm a later finalized checkpoint.
docker compose --env-file "$SETUP/stack.env" -p "$PROJECT" \
  -f "$INSTALL/compose.yml" -f "$INSTALL/compose.offline.yml" up --pull never -d --wait
node scripts/check-standalone-restart.mjs verify "$SETUP"
```

The observer requires a **later** finalized height than the captured baseline.
If `verify` runs before that height exists, wait for node/indexer progress and
retry the read-only check; investigate any other failure before retrying. A
passing simultaneous restart remains pre-deployment smoke, not the separate
service-restart and backup-restore acceptance case `R01`.

## Stop before contract deployment

`observe-stack`, `collect-genesis-candidate`, and the restart observer are the
end of the unattended path. Before running `deploy`, a human must compare the
candidate against an independently reviewed chain specification and sign the
exact wizard genesis approval bytes. Governance must separately approve the
release committee's public keys, threshold, and custody roles. The wizard
status makes these missing gates visible without submitting a transaction:

```sh
node scripts/standalone-setup-wizard.mjs status "$SETUP"
node scripts/check-standalone-journey-prerequisites.mjs "$SETUP" "$SOURCE_SHA"
```

The second command exits 2 until its recorded ledger prerequisites are met.
Even exit 0 is not a full E2E pass: it does not verify the complete key
inventory, authenticated finality, a signed API plan, actor actions, or
host/browser egress denial. A setup created from an older source SHA cannot
qualify a newer candidate. Preserve its evidence, but start a fresh
source-matched setup rather than changing the recorded SHA.

The real deployment and verifier-key CLIs require an approved, root-owned
code tree with no untrusted write access, plus the import-boundary preloader.
Relative pnpm links are allowed only when both their literal and resolved
targets stay inside that tree; a normal writable developer checkout is not an
installed provider. Follow the
[provider execution procedure](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-offline-runtime.md#local-deployment-operator-cli)
only after the signed approvals exist. The current tests exercise this guard,
but a root-owned exact-source install and real SDK-backed deployment have not
yet been qualified. Do not bypass the guard to make the run proceed.

The source checkout can prepare a private, user-owned code stage from the
matching verified bundle without copying ignored wallet or setup files:

```sh
mkdir -m 700 /absolute/private/provider-stages
node scripts/stage-provider-runtime.mjs "$INSTALL" \
  /absolute/private/provider-stages/"$SOURCE_SHA"
```

This requires a clean signed `HEAD` equal to the bundle source SHA. Its output
is **not** the root-owned installation or approval. Independently record the
reported source, inventory, and `contentSha256` digests outside the stage.
After a privileged operator copies the reviewed stage to a new root-owned,
non-writable code tree, check it using those external values:

```sh
node scripts/verify-installed-provider-runtime.mjs \
  /absolute/root-owned/trust-registry-install \
  "$REVIEWED_CONTENT_SHA256" "$REVIEWED_SOURCE_SHA" "$REVIEWED_INVENTORY_SHA256"
```

The checker rejects changed content, layout, metadata, or untrusted ownership;
it does not approve the signer, genesis, or deployment. Never run the provider
from the user-owned stage or include private keys in it.

If ending the smoke run rather than continuing to human approval and
deployment, stop **only** this project. Preserve its volumes and evidence.
When resuming, start it again with the same verified bundle, image tags, and
private environment, wait for health, and re-observe before continuing.

```sh
docker compose --env-file "$SETUP/stack.env" -p "$PROJECT" \
  -f "$INSTALL/compose.yml" -f "$INSTALL/compose.offline.yml" stop
```

## Continue to real end-to-end acceptance

After independent genesis approval, follow the
[full first-run wizard procedure](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-offline-runtime.md#first-run-setup-wizard-initial-slice).
Deploy **once**, reconcile an ambiguous submission instead of retrying, read
back the constructor and every verifier key at an authenticated finalized
checkpoint, then transition to the approved threshold committee. Start the
API only with a human-signed deployment-bound plan.

The [operator acceptance record](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-local-journey.md#operator-acceptance-record)
names cases `L01`-`S01`: issuer/verifier/auditor grants, maintainer and
recognition actions, DID and live VC-status checks, negative authorization
cases, egress-denied actor work, restart and distinct-project restore, and
independent human security review. Record each as `pass`, `fail`, or `not-run`
with raw receipts. After deployment and the signed API plan exist, run the
read-only API observation against the same setup, verified bundle, and exact
signed source revision:

```sh
pnpm observe:standalone-qualification "$SETUP" "$INSTALL" "$SOURCE_SHA"
# Only when this dedicated API may be restarted:
pnpm observe:standalone-qualification "$SETUP" "$INSTALL" "$SOURCE_SHA" --api-restart
```

The command verifies bundle bytes and source identity first, exits 2 without
probing the API while wizard ledger prerequisites are missing, and exits 1 on
invalid bundle or probe failure. Save JSON reports and raw egress logs
privately. With prerequisites present, it checks live current issuer,
verifier, auditor, and recognition reads with API-container TCP/DNS canary
denial. The opt-in flag restarts only the API and requires the same signed
plan and selected state afterward. Neither invocation
submits an actor transaction, authenticates node finality independently,
tests host/browser egress, or restores a ledger backup.

Initialize an acceptance inventory with the reviewed genesis, contract,
source, install inventory, and signed-plan hashes, then attach distinct raw
receipts to each case as described in the operator acceptance record:

```sh
EVIDENCE_DIR=/absolute/private/acceptance
mkdir -m 700 "$EVIDENCE_DIR"
node scripts/check-standalone-acceptance-evidence.mjs init \
  "$EVIDENCE_DIR" "$SOURCE_SHA" "$INVENTORY_SHA256" \
  "$SIGNED_PLAN_SHA256" "$GENESIS_HASH" "$CONTRACT_ADDRESS"
# After saving a redacted raw receipt under $EVIDENCE_DIR/L01/deploy.log:
node scripts/check-standalone-acceptance-evidence.mjs attach \
  "$EVIDENCE_DIR" "$SOURCE_SHA" L01 L01/deploy.log
pnpm check:standalone-acceptance-evidence "$EVIDENCE_DIR" "$SOURCE_SHA"
```

Attaching a file hashes it but deliberately leaves the case `not-run` until
an operator assesses the receipt and changes its verdict. Preserve the raw
file and do not reuse it for a different case.

The checker exits 2 while cases are not marked `pass`, 1 for invalid or
source-mismatched evidence, and 0 only for a complete hash-consistent
inventory. It does not verify whether a receipt, finality claim, or human
verdict is true. Do not mark write-dependent cases as passed from the
read-only probes.

The release remains blocked until those cases pass for one exact source and
bundle, with a non-author human security verdict. The current read-only API
profile cannot by itself complete the write-dependent actor cases. Keep the
promotion PR draft until its local-only scope and all release gates are
explicitly updated and independently reviewed.
