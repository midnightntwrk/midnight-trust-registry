# End-to-end testing: demo versus standalone

There are two different paths. The **demo path** is runnable from a fresh
checkout and exercises the user-facing flows with fixtures and a Compact
simulator. The **standalone acceptance path** requires one independently
approved local ledger deployment, live DID/VC/status services, and operator
evidence. Passing the demo path does not advance the standalone release gate.

## Run the demo path today

Use Node.js 24, the repository's pinned pnpm version, and a fresh checkout.
`./run.sh --light` removes some generated Compact outputs, so run it only in
a disposable checkout, never where full proving keys or a verified install
bundle must be preserved.

```sh
pnpm install --frozen-lockfile
./run.sh --light
pnpm run test:e2e:demo
```

`test:e2e:demo` runs signed issuer, verifier, auditor, and maintainer Compact
simulator journeys, then starts the fixture API and both served UIs on
ephemeral loopback ports. A passing exit code means those two demo checks
passed; it does not imply a deployed contract, authenticated finality, live VC
status, or offline runtime. In an artifact-bearing checkout, **do not run**
`./run.sh --light`: use a disposable checkout for that prerequisite. For the
applicant and admin flows in a real browser, install Google Chrome and run
`pnpm run test:e2e:demo:browser`. This reuses the demo command's built assets
and runs all Playwright specs without invoking the destructive light build.
CI installs Playwright-pinned Chromium instead of Google Chrome. Both variants
still use fixture identity/status and simulator governance; a green CI browser
step is **not** standalone deployment evidence. See the
[demo quickstart](quickstart.md) for individual commands and expected behavior.

## Prepare a standalone run

The first 0.1.0 candidate targets a self-hosted Midnight ledger whose
**runtime** has external egress denied. Installation may be online. Helm and
public networks are not acceptance requirements. Use an isolated Docker
project and private evidence directory; do not reuse another project's node,
wallet, containers, or volumes.

1. Verify the GPG-signed source commit and independently approved digest of
   its exact-source install inventory. Then run
   `node scripts/check-standalone-install.mjs "$INSTALL"`.
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
node scripts/standalone-setup-wizard.mjs status "$SETUP"
node scripts/check-standalone-journey-prerequisites.mjs "$SETUP" "$SOURCE_SHA"
```

Exit 2 means prerequisites are missing. Exit 0 means **only** that the wizard
has recorded its ledger prerequisites; it does not authenticate finality,
enable governed writes, or pass any actor case. The report pairs each missing
gate with a `nextActions` entry. If `sourceMatchesCandidate` is false, start a
new exact-source setup rather than reusing evidence from the older install.
Do not remove an active setup lock or sign an approval on an operator's behalf.
No standalone actor E2E command is currently green by design: the packaged
local-ledger API is read-only, and the issuer/verifier/auditor/maintainer ports
are not supplied by a qualified embedding host. Stop at this preflight rather
than recording the simulator command above as an `A01`-`O01` pass.

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
node scripts/check-standalone-actor-capability.mjs \
  /absolute/private/health.json "$SIGNED_PLAN_SHA256" issuer verifier auditor maintainer recognition
```

A configured port is only a preflight observation, not a successful actor
transaction. The packaged local-ledger API CLI currently has no production
governed-write ports, so this check is expected to stop a full actor run.
An embedding host must supply approved immutable provider code, authenticated
finality, live VC-owned status verification, and the governed ports before
`A01`-`A04` can pass. Do not use simulator or mock-provider receipts in their
place.

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

## What a new adopter can claim

| Evidence | Safe claim |
| --- | --- |
| Demo and simulator tests pass | The reference flows work under their test fixtures. |
| Pinned bundle and isolated stack checks pass | The install bytes and pre-deployment stack passed the checks reported by those commands. |
| Read-only observer passes after deployment | The signed-plan API served the checked current reads and its own container denied the canary egress probes. |
| Every acceptance case has operator-reviewed evidence | The inventory is complete; an independent reviewer must still assess authenticity, finality, security, and release disposition. |

None of these rows alone says that 0.1.0 is release-ready.
