# Standalone local journey: operator quickstart

This is the short path to a **self-hosted, offline-runtime** Trust Registry
qualification run. Installation may use the network; the runtime may not.
Preprod, Preview, Mainnet, Kubernetes, and Helm are not 0.1.0 local-RC gates.
The `standalone` [network profile](../spec/network-profiles.md) supplies the
Midnight SDK network ID (`undeployed`) to the local checkpoint and deployment
readers. That ID is a protocol selector, not a genesis hash or an assertion
that a contract is deployed. Each installation needs its own independently
reviewed genesis pin. A genesis-pinned RPC response from the local node is
operator-node evidence; it does not independently authenticate finality.
The detailed procedures and threat model are in
[Standalone Offline Runtime Qualification](standalone-offline-runtime.md).
The [security-scan disposition](security-scan-disposition.md) explains how to
reproduce the older draft's scanner findings; only an exact-head full scan can
clear that gate for a new candidate. Give the independent reviewer the
[local RC security-review handoff](../plans/local-0.1.0-security-review-handoff.md)
with the exact source and install candidate.

**Current state:** the repository has simulator-backed actor journeys, API
integration tests, pinned-install checks, and pre-deployment local-ledger
restart observations. It has **not** recorded a complete actor journey against
a deployed, finalized standalone contract. A passing `./run.sh --light`,
`pnpm run integration`, or `pnpm run test:standalone-topology` is not that
evidence. Do not promote draft PR #198 or label 0.1.0 release-ready on those
results.

## Evaluate the implementation without operator approvals

Use a fresh, disposable checkout for an orientation run. Do not run the light
target in a checkout holding generated Compact keys, pinned install bundles,
or private setup evidence: it cleans and rebuilds generated outputs. From the
repository root, while installation dependencies are available:

```sh
pnpm install --frozen-lockfile
./run.sh --light
pnpm run check:adversarial-parity -- --require-full
```

The light target runs package, API, documentation, and simulator-backed demo
checks. The parity command should report equal `demoCaseCount` and
`extractedCaseCount`, with `missingCaseCount: 0`; a nonzero exit is a regression.
These commands need no funded wallet, genesis signature, or maintenance keys.
They are useful for evaluating behavior and reproducing CI, but they do not
start a dedicated ledger, deny actor egress, or produce any `L01`-`S01`
deployed acceptance result. Do not attach their output as deployed evidence.
Continue with the operator procedure below only when an exact-source install
candidate and the required independent approvals are available.

The current signed local API CLI is read-only: it does not configure the
production applicant/VP intake, accepted-application admission, governed
proposal ports, or submitting provider. Governed proposal writes return 503.
An opt-in issuer-port assembly exists for an embedding host, but it requires
independently implemented live evidence, authenticated finality, and approved
provider-code dependencies. It is not wired into this CLI; its unit and SDK
tests do not count as the `A01` deployed actor case.
`GET /health` reports `configuredGovernedProposalRoles: []` for this CLI; a
healthy current-read response is not a write-capability or release verdict.
The operator steps below are the **acceptance procedure**, not a claim that
they can all run today. The implementation sequence is in
[Standalone Governed Actor Path](../plans/standalone-governed-actor-path.md).

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
   Keep the review packet with this installation's private evidence, not in a
   PR or a shared log. The proposed pin requires the verified temporary relay
   described in the detailed guide; collect the candidate before attaching
   that relay, and remove it again after drafting the pin:

   ```sh
   node scripts/standalone-setup-wizard.mjs collect-genesis-candidate /absolute/private/setup
   # Attach the reviewed installation relay, then:
   node scripts/standalone-setup-wizard.mjs draft-genesis-pin /absolute/private/setup
   # Stop and remove that relay before continuing:
   pnpm prepare:standalone-genesis-review /absolute/private/setup
   node scripts/check-standalone-journey-prerequisites.mjs /absolute/private/setup "$SOURCE_SHA"
   ```

   Set `SOURCE_SHA` to the full commit used for the verified bundle. Before
   approval, the last command must exit 2 with `genesisApproved` as the first
   missing gate (unless an earlier setup gate is missing). The packet and pin
   remain node-derived, untrusted proposals. The reviewer must authenticate
   the chain specification independently and sign the wizard's later exact
   approval draft, not this packet. Do not proceed to deployment merely
   because the node report matches the proposed pin.
   Once genesis is approved, the prerequisite report must next require the
   signed release roster and its reviewed deployment plan. The wizard rejects
   deployment without this pre-deployment committee approval. The separate
   deployment-bound committee signature can follow finalized deployment
   before the remaining verifier-key insertions. Reconcile every key before
   transitioning maintenance authority; neither signature substitutes for
   the other.
   If `status` reports `invalid-approval-evidence-investigate` for local ledger
   or maintenance approval, stop. Preserve the setup directory and signed
   evidence for investigation; do not edit the record or regenerate an approval
   to bypass the mismatch. The journey prerequisite command exits with an
   investigation error instead of suggesting a new signature. The status
   check compares retained bytes and setup bindings, but does not
   independently authenticate the reviewer key.
4. **Deploy and reconcile once.** Stage the exact signed source and verified
   packages with `stage-provider-runtime.mjs`; independently record its source,
   inventory, and content digests. Transfer it to a new root-owned code tree
   that the non-root operator cannot change, and verify the copy with
   `verify-installed-provider-runtime.mjs` using those externally recorded
   digests. This is an install handoff, not a deployed E2E result. Set
   `TR_IMMUTABLE_PROVIDER_ROOT` and preload
   `scripts/approved-provider-preload.mjs` as described in the
   [local deployment operator CLI](standalone-offline-runtime.md#local-deployment-operator-cli).
   Keep every relative dependency link and its resolved target inside the
   approved tree; a writable development checkout is not a substitute. Use
   wizard `deploy` with the signed plan;
   if the result is ambiguous, use `reconcile-deploy`, never an unreviewed
   second submission. Capture the transaction ID, finalized checkpoint,
   contract address, constructor state, maintenance authority, and every
   verifier-key readback. A missing or stale readback is a stop condition.
5. **Transition authority.** Bind the approved roster to the finalized
   deployment, collect the threshold signatures, submit once, and reconcile
   finalized maintenance readback. A bootstrap-only or development-smoke
   authority is not qualified. Once the wizard reports an unambiguous observed
   transition, export its restricted approval-chain handoff:

   ```sh
   node scripts/standalone-setup-wizard.mjs export-api-approval-chain /absolute/private/setup
   ```

   The command creates a mode-0600, non-overwriting
   `api-approval-chain.json` in that private directory. It retains the three
   signed approval documents, signatures, and a minimal observed maintenance
   receipt, but omits wallet material, provider configuration, and the full
   setup record. Store its printed SHA-256 with the operator evidence. This is
   an **export, not API-side verification**. The command fails on pending,
   conflicting, or incomplete readback. It does not establish independent
   finality or qualify a release.
6. **Start the local API and portals from pinned images.** Sign the API's
   immutable current-state plan, verify it with `trust-registry-api
   check-local-ledger-plan`, initialize the bound proposal journal, and start
   local-ledger mode. Snapshot/workspace/demo mode is not acceptable. The
   signed `tr-local-api-runtime-v3` plan must name the exported approval-chain
   path and SHA-256, as well as the approved genesis and deployed contract.
   The API rechecks the embedded detached signatures, signed hash links,
   custody roster, and committee before serving. It reconstructs the
   maintenance action digest from the approved contract, committee, threshold,
   and counter, and rejects a deployment transaction reused as the maintenance
   receipt. These checks do not independently authenticate finality. Use the same approved
   governance reviewer fingerprint and private public-key keyring in the
   CLI invocation. The local-ledger CLI rejects v2 plans; they are not
   approval-chain evidence. Issue #234
   remains a release gate until independent finality and exact-head review
   establish that this linkage is sufficient for the deployed runtime.
   For a source-pinned operator observation, use the combined command below.
   It verifies the full install bundle, checks wizard-recorded ledger
   prerequisites, and only then runs live current-query and API-container
   egress probes. It does not submit an actor mutation or set an acceptance
   verdict. Save its JSON in a private evidence file and inspect it before
   attaching it to a case. Missing gates exit 2 without touching the API;
   invalid bundles or probe failures exit 1. Exit 0 proves only this read-only
   slice, not release qualification. Set `TR_STACK_NAME` to the wizard's
   approved project; the command also matches its inventory, Docker network,
   approved genesis, and deployed contract to the running signed API plan.
   The aggregate rejects a child result that changes its unobserved actor,
   independent-finality, host/browser egress, or plan-to-deployment scope
   markers; a successful read-only observation cannot promote those gates.
   The current-query probe also requires a valid API container identity,
   process start time, and restart count on both reads around its egress
   test; missing process identity makes the observation inconclusive.

   ```sh
   pnpm observe:standalone-qualification \
     /absolute/private/setup /absolute/verified-bundle "$SOURCE_SHA"
   ```

   Add `--api-restart` only when the dedicated API may be restarted. It checks
   that the signed plan and selected state survive one API-container restart;
   it does not restart the ledger or test restore.
   Before an operator actor run, check the wizard's ledger prerequisites:

   ```sh
   node scripts/check-standalone-journey-prerequisites.mjs /absolute/private/setup "$SOURCE_SHA"
   ```

   Set `SOURCE_SHA` to the full signed commit selected for this install
   candidate, not an old setup record's SHA. A source mismatch is a missing
   gate; rebuild and review a source-matched bundle rather than reusing the
   old deployment evidence. Exit code 2 lists missing gates; exit code 0
   means only that wizard-recorded ledger prerequisites are present. It does
   not authorize deployment. Use `nextSafeAction` for the first step in the
   operator sequence; `blockedActions` names later steps to defer until that
   first gate is resolved. For example, an older setup's source mismatch
   takes precedence over genesis approval or deployment. Re-run the check
   after each completed step rather than treating `nextActions` as a list of
   commands that can all run immediately. It does
   not verify the complete
   verifier-key inventory, signed API plan, authenticated finality, egress
   denial, an actor action, or release readiness.
   Once the approved API is actually running, run the read-only current-query
   slice with the same `TR_STACK_NAME`, `TR_API_APPROVAL_DIR`, `TR_API_UID`,
   `TR_API_GID`, and `TR_API_REVIEWER_FINGERPRINT` used to start it:

   ```sh
   pnpm observe:standalone-current-query /absolute/private/setup /absolute/verified-bundle
   ```

   This checks issuer, verifier, auditor, and recognition current queries
   against the live signed-plan source twice. It also requires the API's
   running project and network, the signed plan's install inventory SHA-256,
   and the plan's genesis and contract address to match the verified bundle
   and wizard-approved setup before probing egress. It requires the
   selected-state SHA-256 to stay fixed around a positive-control TCP and
   DNS egress-denial probe of the same API container. Save its JSON output
   with the raw probe logs in the private evidence directory. An exit code 0
   is **read-only API runtime evidence**, not a governed-write actor journey.
   Inspect `counts`, `resolvedLookups`, and `ambiguousLookups` together.
   An ambiguous issuer, verifier, or auditor lookup is a fail-closed 409,
   not a successful authorization; the observer retains those counts and
   rejects a change in them during the egress probe. The acceptance binder
   rejects a report that omits or contradicts them. The check does not
   authenticate node/indexer finality, cover host/browser
   egress, independently authenticate the deployment/finality evidence (#234),
   or close release gates.
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
   Before soliciting signatures, capture the API health response from its
   isolated container and run `check-standalone-actor-capability.mjs` as shown
   in the [first-run guide](../../docs-site/guide/standalone.md#check-the-actor-port-before-preparing-signatures).
   A missing issuer port or mismatched signed-plan digest is an early stop,
   not a failed on-ledger action. A passing port check is not `A01` evidence.
8. **Restart and restore.** Restart node, indexer, prover, API, and portals
   independently with egress still denied. Show the same deployment and
   historical ledger state at new finalized checkpoints. Restore a backup in
   a distinct isolated project and reject stale/conflicting checkpoints.
   Quarantine ambiguous submissions; do not treat an empty indexer read as
   permission to retry. The proposal-recovery CLI may inspect a v3 candidate
   and verify a distinct reviewer's signed decision, but it cannot authenticate
   finality or clear a reserved journal entry. Preserve that entry and stop
   if the operator cannot prove the original action is invalidated at an
   independently authenticated checkpoint. For an opt-in **API-only** restart
   observation, after the signed-plan current-query probe passes, run:

   ```sh
   pnpm observe:standalone-api-restart /absolute/private/setup /absolute/verified-bundle
   ```

   This restarts the dedicated API container once, repeats the read and
   API-container egress probes, and rejects a changed plan or selected state.
   It does not restart the node, wallet, or portals; it is not backup/restore,
   actor-write, or independently authenticated finality evidence. See issues
   #220 and #230 for the remaining recovery gate.
9. **Review and sign off.** Preserve raw receipts, hashes, commands, logs,
   timestamps, egress-deny evidence, and redacted reviewer decisions in a
   private evidence bundle. An independent human reviewer must record scope,
   exact commit, findings, and verdict under issue #232. Release remains
   blocked while any high/critical finding or required evidence is missing.

## Operator acceptance record

Run the cases below against one approved deployment and one pinned install
inventory. Record `pass`, `fail`, or `not-run` for **each** case; never infer a
pass from simulator tests, a wizard status field, or an HTTP response alone.
Keep the command, UTC time, source SHA, inventory SHA-256, signed-plan SHA-256,
contract address, genesis hash, authenticated finalized checkpoint, and
redacted raw output for each case in the private evidence bundle. Preserve
transaction IDs and journal states for writes. After a mutation, require the
operator-reviewed re-sign/restart before accepting a new current-state read.

| Case | Action and expected result | Required evidence |
| --- | --- | --- |
| `L01` | Approve genesis, deploy once, and read back the constructor, authority, and every verifier key at a finalized checkpoint. | Signed approval, exact-source bundle, deployment journal, authenticated inclusion/readback, complete key-hash comparison. |
| `L02` | Transition from bootstrap authority to the release-approved threshold roster; old bootstrap authority cannot act. | Signed roster, distinct custodian proofs, finalized transition and rejection receipts. The 1-of-3 development roster does not pass. |
| `A01` | Submit issuer application with local DID/VC/status evidence; governed proposal and decision create a current issuer grant. | Accepted evidence commitment, exact-intent signatures, one-attempt journal, finalized event and by-ID/current API readback. |
| `A02` | Repeat `A01` for verifier and auditor grants, including their distinct policy and mandate scopes. | Separate finalized receipts and current reads for each role; no role substitution. |
| `A03` | Perform a maintainer-governed action and a scoped external-authority recognition decision. | Threshold signatures, finalized action sequence/events, current maintenance and recognition readback. Recognition must not imply membership. |
| `A04` | Resolve the issuer DID and validate the live VC status authority; relying party checks current evidence and TRQP against the same local deployment. | Authenticated DID/status responses, trusted-time decision, selected finalized checkpoint, API/TRQP outputs. A fixture status response fails. |
| `N01` | Reject wrong authority, stale signed plan, substituted evidence, revoked or suspended grant, and unavailable local status. | Per-case denial with no unintended ledger mutation; uncertain submissions remain quarantined. |
| `O01` | Repeat actor reads and a governed action with external egress denied while local service traffic remains available. | Host/container/wallet/browser/prover egress logs, positive controls, receipts and readbacks from the same deployment. API-container canary denial alone does not pass. |
| `R01` | Restart each service, then restore a backup in a distinct isolated project; reject stale or conflicting checkpoint and reconcile an ambiguous submission without blind retry. | Before/after authenticated checkpoints, contract and journal state, restore logs, operator recovery decision. |
| `S01` | Have a non-author human assess the exact candidate and all retained evidence. | Reviewer identity, scope, findings, dispositions, and release-owner sign-off under issue #232. |

Do not mark the end-to-end journey complete unless `L01` through `S01` all
pass at a single reviewed candidate SHA. These cases are an acceptance
procedure, not evidence that any deployed run has occurred. The current
read-only query probe can support part of `A04`; it cannot satisfy `A01` to
`A03`, `O01`, or `R01`.

### Hand off one evidence bundle

After deployment and the signed API plan exist, make a private directory and
initialize an acceptance inventory with the **actual** source revision,
install-inventory SHA-256, signed-plan SHA-256, reviewed genesis hash, and
deployed contract address. The final two values must be lowercase `0x`-prefixed
64-hex-character values. All five identifiers must be nonzero; the initializer
rejects all-zero placeholders but does not authenticate the supplied values.
Do not use a node-reported genesis candidate or a simulator address as a substitute.

```sh
mkdir -m 700 /absolute/private/acceptance
node scripts/check-standalone-acceptance-evidence.mjs init \
  /absolute/private/acceptance "$SOURCE_SHA" "$INVENTORY_SHA256" \
  "$SIGNED_PLAN_SHA256" "$GENESIS_HASH" "$CONTRACT_ADDRESS"
```

For each case in `acceptance.json`, record `pass`, `fail`, or `not-run`
**only after reviewing the underlying run**. Put its redacted raw command
output/receipts under that private directory. Attach each file with the
helper, which hashes it and updates the case inventory atomically while
leaving its status unchanged:

Use `umask 077` when capturing evidence. The acceptance root and each nested
evidence directory must be mode `0700`; every attached raw receipt and
observation must be mode `0600`, a regular file with one link. The checker
rejects public files or directories even when their content hash matches.
For an older bundle, inspect ownership and each path before restricting its
mode; do not follow symlinks or regenerate a signed decision to bypass a
failed check. Keep wallet secrets and unredacted holder data out of the bundle.

```sh
node scripts/check-standalone-acceptance-evidence.mjs attach \
  /absolute/private/acceptance "$SOURCE_SHA" L01 L01/deploy.log
```

After inspecting the raw evidence, record an explicit operator decision.
Use a stable reviewer identifier and a non-sensitive reason code; put detailed
reasoning in a separately attached private file rather than command arguments:

```sh
node scripts/check-standalone-acceptance-evidence.mjs decide \
  /absolute/private/acceptance "$SOURCE_SHA" L01 pass \
  operator:alice finalized-readback-reviewed
```

`decide` requires attached raw evidence for `pass` or `fail`. It creates a
mode-0600 decision record under `decisions/`, records the previous status and
all attached evidence hashes, and adds its own hash to the same case under the
inventory lock. A later change to `fail` or `not-run` creates another record;
it does not overwrite the earlier decision. Decision history is limited to
64 records per case, separate from the 32 raw files allowed per case, so a full raw
evidence inventory cannot prevent an operator from revoking a verdict.
These records are self-attested,
not signatures or independent evidence verification. For `S01`, attach the
non-author human's separately signed security verdict before recording `pass`.
The reviewer may sign a private `tr-local-security-verdict-v2` JSON document
with `sourceRevision`, `installInventorySha256`, `signedPlanSha256`,
`genesisHash`, `contractAddress`, `reviewerFingerprint`, `reviewedAt`,
`scope: "self-hosted-local-0.1.0"`, `outcome: "approve"` or `"reject"`,
`findingsPath`, and `findingsSha256`. The findings report must list the review
scope, each finding with severity and reproduction, its disposition and risk
owner, or explicitly say there were no findings. Do not include secrets.
Encode it as canonical two-space-indented JSON with one trailing newline;
duplicate keys or alternate encodings are rejected. Keep the verdict and its
signature as separate flat private files in the acceptance directory. Attach
the findings report, verdict, and detached signature as distinct raw `S01`
evidence before verification. The signed verdict must hash that exact report.
Verify using a reviewer fingerprint pinned **outside** the evidence bundle:

```sh
shasum -a 256 "$EVIDENCE/findings.md" # Put this digest in findingsSha256 before signing.
gpg --batch --yes --detach-sign --output "$EVIDENCE/verdict.sig" \
  "$EVIDENCE/verdict.json" # Run only in the independent reviewer's environment.
chmod 600 "$EVIDENCE/verdict.sig"
node scripts/check-standalone-security-verdict.mjs "$EVIDENCE" "$SOURCE_SHA" \
  verdict.json "$REVIEWER_PUBLIC_KEY" verdict.sig "$PINNED_REVIEWER_FINGERPRINT"
```

This checks the detached signature, findings digest, and exact candidate binding only. It does
not establish that the key belongs to an independent human, that findings were
resolved, or that any deployed receipt is authentic. The release owner must
review those facts and retain the attributable finding disposition under #232.
Never treat a CLI verdict as proof of its underlying receipt or finality.
The inventory reports `completeInventory: true` only when every case's latest
`pass` is backed by a private decision record covering the attached evidence.
If new raw evidence is attached after a `pass`, the case becomes incomplete
until the operator reviews it and records a new decision. Editing a status
label in `acceptance.json` is not a substitute for `decide`; the checker
rejects a label that contradicts the latest decision. These protections catch
stale or accidental inventory edits, not a malicious operator who controls the
private evidence directory.
For an older inventory whose status was entered manually, review the raw
evidence and run `decide` with the desired verdict; its first decision records
the previous label and brings the case into the checked decision chain. Do
not reset or rewrite retained evidence merely to satisfy the new check.

Use a different relative file for each case. The inventory rejects a reused
path even when names differ only by case or Unicode normalization; do not
rename one receipt to make it count for two cases. The manifest itself cannot
be attached as evidence. If `.acceptance.lock` exists,
check whether an evidence writer is active before removing a stale lock; do
not start a competing writer. A `pass` must have at least one raw file. Record the
command, UTC time, checkpoint, operator decision, and relevant transaction or
journal identifier **in the retained file**; the checker does not infer these
facts. Do not include seeds, private keys, or credentials. Keep each raw file
below 32 MiB and use separate files per case.

```sh
pnpm check:standalone-acceptance-evidence /absolute/private/acceptance "$SOURCE_SHA"
```

Pass the full signed source commit selected for the **current** install candidate;
the checker rejects a bundle from a different commit instead of validating
stale acceptance evidence. Exit 2 means at least one case is not `pass`; exit 1
means the source differs or the inventory or a file is invalid, missing,
symlinked, or hash-mismatched. Exit 0 means only
that all cases have current `pass` decisions and every listed file matches
its digest. The
report **always** says `releaseQualified: false`: this command cannot verify
receipt authenticity, ledger finality, the correctness of a human security
verdict, or the truth of a `pass` label. A second operator must examine the
raw evidence and independently disposition the release gates.

### Bind a read-only observation to this candidate

After the approved API is running, capture the combined read-only probe in the
private acceptance directory. Use `umask 077` so the report is not readable by
other local users. An exit code of 2 means a prerequisite is missing; retain
the report for diagnosis, but do not mark a case passed. The probe must run
against the same source revision and install bundle used for `acceptance.json`.

```sh
umask 077
node scripts/observe-standalone-qualification.mjs \
  /absolute/private/setup /absolute/verified-bundle "$SOURCE_SHA" \
  > /absolute/private/acceptance/read-only-observation.json
node scripts/check-standalone-acceptance-evidence.mjs observe \
  /absolute/private/acceptance "$SOURCE_SHA" read-only-observation.json
```

The second command compares the report's source, inventory, signed API-plan
hash, approved genesis, and deployed contract with the acceptance candidate.
It also rejects nested read-only reports that claim actor success, independent
finality, host/browser egress verification, or a release verdict, and requires
the API TCP/DNS canary-denial observations to remain present.
It exits 0 only for a matching read-only observation, 2 for an observation
stopped before the API probe, and 1 for invalid or mixed-candidate evidence.
It requires a private regular file, does not change `acceptance.json`, and
never marks `A04` or another case passed. It cannot independently authenticate
the report, ledger finality, actor mutations, or the security verdict. An
operator may attach the report as supporting evidence only after checking its
raw probe logs and provenance; the full `A04` live VC-status requirement still
needs separate evidence.

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
