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
with raw receipts. `pnpm check:standalone-acceptance-evidence "$EVIDENCE_DIR"`
checks inventory integrity, not whether the claims or finality are true.

The release remains blocked until those cases pass for one exact source and
bundle, with a non-author human security verdict. The current read-only API
profile cannot by itself complete the write-dependent actor cases. Keep the
promotion PR draft until its local-only scope and all release gates are
explicitly updated and independently reviewed.
