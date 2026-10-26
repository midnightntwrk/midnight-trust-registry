# Standalone local journey: operator quickstart

This is the short path to a **self-hosted, offline-runtime** Trust Registry
qualification run. Installation may use the network; the runtime may not.
Preprod, Preview, Mainnet, Kubernetes, and Helm are not 0.1.0 local-RC gates.
The detailed procedures and threat model are in
[Standalone Offline Runtime Qualification](standalone-offline-runtime.md).

**Current state:** the repository has simulator-backed actor journeys, API
integration tests, pinned-install checks, and pre-deployment local-ledger
restart observations. It has **not** recorded a complete actor journey against
a deployed, finalized standalone contract. A passing `./run.sh --light`,
`pnpm run integration`, or `pnpm run test:standalone-topology` is not that
evidence. Do not promote draft PR #198 or label 0.1.0 release-ready on those
results.

## What the operator needs

- A dedicated local Midnight node, indexer, proof server, funded local wallet,
  and reviewed source-matched install bundle with immutable package, image,
  and proving-artifact hashes. Never reuse another project's volumes.
- A real chain-spec/genesis pin reviewed independently of node-reported
  values, plus the human reviewer's public signing key and detached signature
  on the exact wizard approval bytes. A demo or proposed pin is not approval.
- Governance-approved maintenance public keys, threshold, custody roles, and
  enough independent key holders to sign the deployment-bound transition.
  The development 1-of-3 smoke roster is not a release approval.
- Local DID, VC, and status-authority services and their pinned trust anchors.
  Do not replace the VC-owned live status adapter with a fixture response.
- An egress-deny policy covering the host, wallet, containers, browser, backup
  process, and proof server, with logs and a positive-control test.
- An independent human security reviewer and an operator who owns backup and
  recovery decisions. Do not send seeds, private keys, or credentials in PRs.

## Run in order

1. **Verify the install candidate while online.** Use a signed source commit
   and the exact-source `artifacts:standalone-install` workflow in the detailed
   guide. Preserve the inventory, release manifest, image digests, verifier-key
   hashes, and all Compact proving artifacts. Record the source SHA and
   inventory SHA-256 in the private evidence directory. A bundle built from a
   different source SHA is a stop condition.
2. **Prepare a new isolated ledger.** Create a fresh mode-0700 setup directory,
   then use the wizard's `init`, `prepare-stack`, and `observe-stack` commands.
   Review the generated Compose plan before starting it. Run `status` after
   every phase:

   ```sh
   node scripts/standalone-setup-wizard.mjs init /absolute/private/setup /absolute/verified-bundle
   node scripts/standalone-setup-wizard.mjs prepare-stack /absolute/private/setup tr-standalone-local-qualification 39944 38088 36300
   node scripts/standalone-setup-wizard.mjs status /absolute/private/setup
   ```

   Use [the detailed stack-start instructions](standalone-offline-runtime.md#first-run-setup-wizard-initial-slice)
   for the reviewed Compose invocation and installation relay. The wizard
   does not start the ledger or approve genesis for you.
3. **Stop at human approvals.** Collect the node's *untrusted* genesis
   candidate, compare it with independently reviewed chain-spec evidence, and
   have the reviewer sign the exact generated approval draft. Review and sign
   the maintenance roster separately. Do not use the demo-reference script,
   a node-reported hash alone, or an AI-generated signature as approval.
4. **Deploy and reconcile once.** Use wizard `deploy` with the signed plan;
   if the result is ambiguous, use `reconcile-deploy`, never an unreviewed
   second submission. Capture the transaction ID, finalized checkpoint,
   contract address, constructor state, maintenance authority, and every
   verifier-key readback. A missing or stale readback is a stop condition.
5. **Transition authority.** Bind the approved roster to the finalized
   deployment, collect the threshold signatures, submit once, and reconcile
   finalized maintenance readback. A bootstrap-only or development-smoke
   authority is not qualified.
6. **Start the local API and portals from pinned images.** Sign the API's
   immutable current-state plan, verify it with `trust-registry-api
   check-local-ledger-plan`, initialize the bound proposal journal, and start
   local-ledger mode. Snapshot/workspace/demo mode is not acceptable. The
   signed plan must identify the approved genesis and deployed contract;
   unresolved plan-to-deployment binding in issue #234 remains a stop gate.
7. **Disconnect external egress, then run the actor use case.** Keep the local
   service network and loopback available. Record issuer application and
   governed authorization, verifier and auditor decisions, maintainer action,
   external-authority recognition, DID resolution, VC status validation, and
   relying-party current-state/TRQP reads. For each mutation, record the
   exact-intent authorization, proposal journal state, transaction/receipt,
   authenticated finalized checkpoint, contract event and readback, and the
   manually reviewed, re-signed API plan used after restart. Include negative
   cases for wrong authority, stale plan, revoked/suspended authorization,
   substituted evidence, and unavailable local status. Browser/API success
   alone is not ledger success. The full actor path is tracked in issue #219.
8. **Restart and restore.** Restart node, indexer, prover, API, and portals
   independently with egress still denied. Show the same deployment and
   historical ledger state at new finalized checkpoints. Restore a backup in
   a distinct isolated project and reject stale/conflicting checkpoints.
   Quarantine ambiguous submissions; do not treat an empty indexer read as
   permission to retry. See issues #220 and #230.
9. **Review and sign off.** Preserve raw receipts, hashes, commands, logs,
   timestamps, egress-deny evidence, and redacted reviewer decisions in a
   private evidence bundle. An independent human reviewer must record scope,
   exact commit, findings, and verdict under issue #232. Release remains
   blocked while any high/critical finding or required evidence is missing.

## Evidence verdict

Use these labels consistently:

| Label | What it proves | What it does not prove |
| --- | --- | --- |
| `simulator-test` | Contract/client behavior under test fixtures | Deployment or finality |
| `ledger-bridge-smoke` | Isolated local node/indexer/prover topology or continuity | A deployed registry or actor journey |
| `deployed-readback` | A specific finalized contract state and verifier-key set | Offline actor success or recovery |
| `offline-actor-journey` | Recorded actor path against the bound local deployment with egress denied | Independent security approval |
| `release-qualified` | All local RC gates, including human review, are satisfied | Preprod or public-network readiness |

The wizard currently reports `releaseQualified: false` and leaves offline
journeys and restore pending. Do not edit those fields or substitute a manual
checklist result. Only promote after the evidence above is independently
reviewed and the outstanding security gates are closed.
