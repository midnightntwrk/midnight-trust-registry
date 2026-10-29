# End-to-end testing: demo versus standalone

There are two different paths. The **demo path** is runnable from a fresh
checkout and exercises the user-facing flows with fixtures and a Compact
simulator. The **standalone acceptance path** requires one independently
approved local ledger deployment, live DID/VC/status services, and operator
evidence. Passing the demo path does not advance the standalone release gate.

## Choose the test you need

| Goal | Run | Passing result means |
| --- | --- | --- |
| Try the product flows without a ledger | `pnpm run test:e2e:demo` | The four signed role journeys and fixture API/UI smoke completed in a Compact simulator. |
| Exercise the demo in a browser | `pnpm run test:e2e:demo:browser` | The same demo plus applicant/admin Playwright flows completed against fixture services; the test context blocked and reported non-loopback browser requests. |
| Check submission restart quarantine without a live network | `pnpm --filter @midnight-ntwrk/trust-registry-api run test:light` | The journal write, mocked-node/provider restart, and fixture API-listener restart tests passed; this is not deployed-ledger recovery evidence. |
| Check a real standalone candidate before actor testing | `node scripts/check-standalone-journey-prerequisites.mjs "$SETUP" "$SOURCE_SHA"` | Exit 0: the wizard recorded the prerequisite ledger observations for this exact source. Exit 2: stop and follow `nextActions`. |
| Record a deployed candidate's operator-reviewed cases | `node scripts/check-standalone-acceptance-evidence.mjs "$ACCEPTANCE" "$SOURCE_SHA"` | Exit 0: all cases have a current decision-backed operator `pass`; exit 2: a case is failed, not run, or needs a fresh decision. Inspect `operatorFailedCases`, `notRunCases`, and `decisionBackedCases`; receipt authenticity, finality, and the security verdict still need independent review. |

There is deliberately no green standalone actor-E2E shortcut. A demo result,
successful prerequisite check, or complete evidence inventory cannot substitute
for real actor transactions on a reviewed, finalized, egress-denied local
deployment.

## Run the demo path today

Use Node.js 24, the repository's pinned pnpm version, and a fresh checkout.
`./run.sh --light` removes some generated Compact outputs, so run it only in
a disposable checkout, never where full proving keys or a verified install
bundle must be preserved.

```sh
pnpm install --frozen-lockfile
./run.sh --light
pnpm run test:e2e:demo
pnpm exec playwright test
```

`test:e2e:demo` first checks that prebuilt Compact output contains the current
source and contract module. If generated source declarations are absent, it
restores only that contract module from the preserved `dist` copy; mismatched
generated source stops the run. It then compiles contract TypeScript helpers in
place and rebuilds downstream TypeScript and UI workspaces
without regenerating Compact keys. It runs signed issuer, verifier, auditor,
and maintainer Compact simulator journeys, then starts the fixture API and
both served UIs on ephemeral loopback ports. A passing exit code means those
two demo checks passed; it does not imply a deployed contract, authenticated finality, live VC
status, or offline runtime. In an artifact-bearing checkout, **do not run**
`./run.sh --light`: use a disposable checkout for that prerequisite. The demo
command fails if the required prebuilt Compact output is absent or stale;
it never repairs it by invoking `build:light`. For the applicant and admin
flows in a real browser, run `pnpm exec playwright install chromium` and then
the Playwright command above (or `pnpm run test:e2e:demo:browser` to rerun both
lanes). If the browser is unavailable, report that lane as **not run** rather
than passed. Neither result is a standalone `A01`-`O01` verdict.
If full Compact outputs already exist in an artifact-bearing checkout, use
`pnpm run integration:prebuilt` for the package and simulator integration lane.
It checks all 66 full proof circuits, compiles contract helpers, and rebuilds
downstream TypeScript/UI packages without calling the Compact build or removing
its `dist` tree. It does not establish
the provenance of those artifacts or count as a deployed standalone actor run.
CI and the default local configuration use Playwright-pinned Chromium; set
`TR_BROWSER_CHANNEL=chrome` to test separately installed Google Chrome. Both variants
still use fixture identity/status and simulator governance; a green CI browser
step is **not** standalone deployment evidence. The browser suite also checks
that the local-ledger admin view hides fixture mutation controls and discards
an exact-ID result when a mocked API checkpoint changes mid-request. This is
a UI fail-closed regression, not a deployed-ledger or authenticated-finality
test. Its Playwright context blocks service workers and audits HTTP and
WebSocket requests, failing if any unregistered origin is attempted. HTTP
redirects are denied even when their destination is loopback, so an allowed
fixture response cannot trigger an unguarded follow-up request. That
guard accepts only each test's registered ephemeral loopback origin, not every
host-local port. An unrelated loopback service is denied and recorded. The
guard covers only requests visible to this fixture browser context; it does
not prove host, wallet, prover, container, or deployed-browser egress denial.
The fixture lane includes negative probes for a loopback HTTP redirect to a
reachable non-loopback listener and a direct WebSocket attempt to that
listener. Both must be blocked and recorded by the browser audit. They do
not replace the deployed `O01` egress-denied actor run.
See the
[demo quickstart](quickstart.md) for individual commands and expected behavior.

## Prepare a standalone run

The first 0.1.0 candidate targets a self-hosted Midnight ledger whose
**runtime** has external egress denied. Installation may be online. Helm and
public networks are not acceptance requirements. Use an isolated Docker
project and private evidence directory; do not reuse another project's node,
wallet, containers, or volumes.

Start with the [operator quickstart](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-local-journey.md), not the demo commands. Keep one private candidate record with the full signed source SHA, install-inventory SHA-256, approved genesis hash, deployed contract address, signed API-plan SHA-256, and local stack project. If any identity changes, start a new candidate rather than joining receipts from two runs.

1. Verify the GPG-signed source commit and independently approved digest of
   its exact-source install inventory. Then run
   `node scripts/check-standalone-install.mjs "$INSTALL" "$SOURCE_SHA"`.
   The second argument is the selected full commit SHA; a valid bundle from
   another revision is rejected before setup. Internal hash verification does
   not replace independent provenance review.
2. Follow [the standalone first run](standalone.md) to initialize the wizard,
   load the pinned images, observe the local stack, and collect an **untrusted**
   genesis candidate. The unattended path stops there.
3. An independent operator reviews the real chain specification and signs
   the exact genesis approval. Governance approves the maintenance roster,
   public keys, threshold, and custody roles separately. A development 1-of-3
   roster and `demo:` reference cannot qualify a release.
4. Deploy once through the approved immutable provider installation. If a
   submission is ambiguous, reconcile it; never blindly retry. Require
   authenticated finalized constructor, maintenance-authority, and complete
   verifier-key readback. Transition to the approved committee and sign the
   deployment-bound current API plan.

Check the recorded prerequisite gates before starting an actor run:

```sh
SOURCE_SHA="$(git rev-parse HEAD)"
SETUP=/absolute/private/setup
INSTALL=/absolute/verified-bundle
node scripts/check-standalone-install.mjs "$INSTALL" "$SOURCE_SHA"
node scripts/standalone-setup-wizard.mjs status "$SETUP"
node scripts/check-standalone-journey-prerequisites.mjs "$SETUP" "$SOURCE_SHA"
```

Exit 2 means prerequisites are missing. Exit 0 means **only** that the wizard
has recorded its ledger prerequisites; it does not authenticate finality,
enable governed writes, or pass any actor case. The report pairs each missing
gate with a `nextActions` entry. If `sourceMatchesCandidate` is false, start a
new exact-source setup rather than reusing evidence from the older install.
Exit 1 means the input or setup could not be checked; do not interpret it as
a missing gate that can be waived.
In particular, `invalid-approval-evidence-investigate` in the wizard status
means retained genesis or committee approval evidence no longer agrees with
the private setup and pinned install. The prerequisite command exits 1 in
this state. Preserve the setup directory and signed bytes for investigation;
do not regenerate an approval, edit the record, or proceed to deployment or
maintenance transition. A status label is not an independent GPG or finality
verification.
The preflight also rejects approval labels without a nonzero approved genesis
hash or deployed contract address, and duplicate or unnamed staged verifier
keys. This preflight does not compare that list with the complete release
manifest or independently authenticate a receipt. The separate aggregate
observer compares the recorded key catalog with the verified install bundle;
that comparison is still not an on-chain key readback.
Do not change `SOURCE_SHA` to the older setup's revision just to make this
check pass: the source, install bundle, API plan, and acceptance inventory must
identify the same candidate. This command is safe to rerun and does not deploy
or modify the ledger.
Do not remove an active setup lock or sign an approval on an operator's behalf.
No standalone actor E2E command is currently green by design: the packaged
local-ledger API is read-only, and the issuer/verifier/auditor/maintainer ports
are not supplied by a qualified embedding host. Stop at this preflight rather
than recording the simulator command above as an `A01`-`O01` pass.

Once the approved read-only API is running, bind its aggregate observation to
the same private acceptance candidate. Use the full selected source revision
and retain the raw probe output for operator review:

```sh
umask 077
node scripts/observe-standalone-qualification.mjs \
  "$SETUP" "$INSTALL" "$SOURCE_SHA" \
  > /absolute/private/acceptance/read-only-observation.json
node scripts/check-standalone-acceptance-evidence.mjs observe \
  /absolute/private/acceptance "$SOURCE_SHA" read-only-observation.json
```

The binder rejects a missing or overstated verifier-key catalog marker and
mixed source, inventory, plan, genesis, or contract identities. Exit 0 means
only that a matching **read-only** observation was bound; exit 2 means the API
probe was blocked by prerequisites. It does not pass an acceptance case or
authenticate finality, actor actions, or the report itself. See the
[operator acceptance record](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-local-journey.md#bind-a-read-only-observation-to-this-candidate)
for the full evidence boundary.

## Run and record the real use case

The [operator acceptance record](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-local-journey.md#operator-acceptance-record)
defines one candidate-bound set of cases. Keep the source SHA, install
inventory, signed API plan, genesis, contract address, and finalized
checkpoint consistent across all of them.

| Cases | What must happen on the deployed local ledger |
| --- | --- |
| `L01`-`L02` | Deployment and verifier-key readback, then the approved threshold-maintenance transition. |
| `A01`-`A04` | Issuer, verifier, auditor, maintainer, recognition, DID, VC live-status, current API, and relying-party reads. |
| `N01`, `O01` | Denials without unintended mutations, and actor work with external egress denied. |
| `R01`, `S01` | Service restart, distinct-project restore, ambiguous-write reconciliation, and independent human security review. |

Before collecting signatures, save the live API `/health` response and check
that the required proposal ports match the signed plan:

```sh
umask 077
node scripts/check-standalone-actor-capability.mjs \
  /absolute/private/health.json "$SIGNED_PLAN_SHA256" issuer verifier auditor maintainer recognition
```

Capture `health.json` as a mode-0600 regular file in a private directory.
The preflight rejects symlinks, hard links, and group/world-readable files;
it still cannot independently authenticate the saved response.

A configured port is only a preflight observation, not a successful actor
transaction. The packaged local-ledger API CLI currently has no production
governed-write ports, so this check is expected to stop a full actor run.
An embedding host must supply approved immutable provider code, authenticated
finality, live VC-owned status verification, and the governed ports before
`A01`-`A04` can pass. Do not use simulator or mock-provider receipts in their
place.
Before exposing applicant challenge issuance beyond a trusted local operator,
the host must authenticate the applicant and return its verified DID from
`authorizeRequest`. The challenge service rejects a DID that differs from the
pending application, and the reference stores enforce a live per-subject quota
atomically across local processes. This is not a built-in DID authentication
method: a caller-provided DID or demo header is not a quota identity. The
packaged local-ledger API has no production applicant port. Keep public
issuance disabled until a real authenticated host and durable atomic VP
verification have been independently implemented and tested.
The [standalone actor host handoff](standalone-actor-host.md) lists the
required callbacks, result bindings, and negative cases without treating an
injected test provider as a deployed runtime.
For issuer writes, it must also verify the detached reviewer signature on the
writer annex, bind it to the exact signed API plan and installed provider
content, require the same verified plan reviewer fingerprint, and initialize
the API-owned submission journal at the annex's path.
The opt-in issuer port tests exercise this boundary with injected providers;
they are not a deployed local-ledger actor journey.

When a reviewed v3 API plan and immutable provider installation exist, draft
the issuer-writer approval for the embedding host in a private directory:

```sh
pnpm --filter @midnight-ntwrk/trust-registry-api build
node scripts/prepare-local-issuer-writer-review.mjs \
  "$PRIVATE_REVIEW_DIR" "$SIGNED_PLAN" "$PLAN_SIGNATURE" "$REVIEWER_KEYRING" \
  "$REVIEWER_FINGERPRINT" "$INSTALLED_PROVIDER_ROOT" \
  "$INDEPENDENTLY_REVIEWED_PROVIDER_CONTENT_SHA256" "$ABSOLUTE_JOURNAL_PATH"
```

The content digest must come from an independently reviewed handoff, never
from trusting the installed tree's own report. The command verifies the plan
signature and provider bytes, then writes `issuer-writer-approval.unsigned.json`
without overwriting existing review bytes. It does not sign the file or turn
on a writer. After reviewing every field, the human plan reviewer may sign
those exact bytes with their own GPG key; the embedding host must verify that
detached signature and the plan-reviewer identity before use. Never place a
private signing key in the install bundle or repository. This is preparation,
not an `A01` pass or independent finality evidence.
After the human has reviewed and signed those exact bytes, run the read-only
preflight against the signed plan, detached signatures, and installed provider:

```sh
node scripts/check-local-issuer-writer-approval.mjs \
  "$SIGNED_PLAN" "$PLAN_SIGNATURE" "$SIGNED_WRITER_APPROVAL" \
  "$WRITER_SIGNATURE" "$REVIEWER_KEYRING" "$REVIEWER_FINGERPRINT"
```

Its success verifies the approval and installed-provider pins only. The
report explicitly leaves `actorJourney` and `independentFinality` unverified;
the host must still assemble and qualify a live writer before `A01` can pass.

The [read-only qualification observer](standalone.md#continue-to-real-end-to-end-acceptance)
can validate the approved API's current queries and API-container egress
denial after deployment. It cannot submit a governed action or prove host,
wallet, browser, and proof-server egress denial. Record its output as partial
evidence only.

Initialize a private acceptance inventory **after** real deployment and a
signed API plan exist. Attach each case's raw redacted receipts, then have an
operator record an explicit case verdict. The inventory checker hashes the
files and tracks missing cases; it does not independently verify receipt
truth, reviewer identity, or release readiness.
Keep the acceptance directory and each nested evidence directory mode `0700`,
and every raw receipt or observation file mode `0600` before attaching it.
The checker rejects public, linked, or symlinked evidence; do not loosen file
permissions or copy unredacted wallet, credential, or holder data into the bundle.

```sh
mkdir -m 700 /absolute/private/acceptance
node scripts/check-standalone-acceptance-evidence.mjs init \
  /absolute/private/acceptance "$SOURCE_SHA" "$INVENTORY_SHA256" \
  "$SIGNED_PLAN_SHA256" "$GENESIS_HASH" "$CONTRACT_ADDRESS"
node scripts/check-standalone-acceptance-evidence.mjs \
  /absolute/private/acceptance "$SOURCE_SHA"
```

The full `attach` and `decide` procedure is in the
[operator guide](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-local-journey.md#hand-off-one-evidence-bundle).
The independent human security assessment remains a release gate. Keep draft
promotion #198 draft until the local-only scope and all release gates are
explicitly updated and satisfied.
`completeInventory` and the command's exit code describe current,
decision-backed operator passes, not independent verification.
`operatorFailedCases` and `notRunCases` identify unfinished or disputed cases;
`allOperatorCasesPassed` is false when any case is failed, not run, or lacks a
current decision. `releaseQualified` remains false even when every operator
case is recorded as `pass`.

## What a new adopter can claim

| Evidence | Safe claim |
| --- | --- |
| Demo and simulator tests pass | The reference flows work under their test fixtures. |
| Pinned bundle and isolated stack checks pass | The install bytes and pre-deployment stack passed the checks reported by those commands. |
| Read-only observer passes after deployment | The signed-plan API served the checked current reads and its own container denied the canary egress probes. |
| Every acceptance case has operator-reviewed evidence | The inventory is complete; an independent reviewer must still assess authenticity, finality, security, and release disposition. |

None of these rows alone says that 0.1.0 is release-ready.
