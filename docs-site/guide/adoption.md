# Start here: try, then qualify

The Trust Registry has two paths. **Try the use case** runs a complete
applicant-to-decision reference flow with a Compact simulator and fixture
identity/status services. **Qualify a self-hosted installation** runs against
an independently approved, deployed local Midnight ledger with external
runtime egress denied. The first path is available today; its results cannot
be used as evidence for the second.

## Try the use case

From a fresh checkout, install Node.js 24, the repository's pinned `pnpm`,
and the Compact toolchain (`nix develop` provides the repository toolchain):

```sh
pnpm install --frozen-lockfile
./run.sh --light
pnpm run test:e2e:demo
```

The last command exercises signed issuer, verifier, auditor, and maintainer
journeys, the fixture HTTP API, and both served UIs. Expect four JSON journey
reports followed by `[demo-smoke] Verified CLI/API demo flow and both served UI
surfaces on ephemeral loopback ports.` An exit code of zero means the **demo**
passed, not that a contract was deployed or a VC status authority was checked
on a real ledger. Install Playwright's pinned Chromium with
`pnpm exec playwright install chromium`, then run `pnpm exec playwright test`
to exercise the applicant and admin flows in a real browser. Google Chrome
is optional: set `TR_BROWSER_CHANNEL=chrome` to select it explicitly. Report
the browser lane as not run if no supported browser is installed.

`./run.sh --light` removes generated Compact outputs. Never run it in a
checkout holding full proving keys, a verified install bundle, or private
approval evidence. Once source-matched Compact output is already present,
`test:e2e:demo`, the individual demo aliases, and `test:browser` compile only
contract helpers and downstream TypeScript/UI packages while preserving the
Compact output. Use `pnpm run integration:prebuilt`
for the broader prebuilt simulator integration lane; neither command is a
standalone deployment test. See the [demo details](quickstart.md) and
[test boundaries](end-to-end-testing.md).

### Desktop UI acceptance trial

Ask an engineer who did not build these screens to follow the
[local UI setup](ui-acceptance.md#run-locally) without live guidance. Have them
record the first action they expect at each step, what they actually did, and
any label or state they could not explain:

1. Open the ordinary applicant portal and admin console without `demo=1`.
   Identify the source badge, find Workspace settings, and explain why a
   fixture record is not a finalized trust decision.
2. In the portal, choose issuer, verifier, auditor, and maintainer in turn.
   Find the next preparation step for each role. Choosing a role must not
   submit a request; private submission needs an authenticated same-origin
   host and an external signature.
3. In admin, find an active record, inspect its source and lifecycle meaning,
   filter the review list, and locate (but do not submit) a governed action.
   Confirm the selected detail never implies an on-chain grant for a fixture.
4. Repeat the main navigation, one role choice, record selection, and Workspace
   settings at a desktop width by keyboard and screen reader. Check the spoken
   names, expanded state, focus order, error/status announcements, and 200%
   text zoom. Do not infer screen-reader usability from an axe pass.

Report each step as passed, failed, or not run, with the browser, viewport,
assistive technology and version, source label, observed action/result, and a
screenshot or concise reproduction for each failure. Use the
[desktop review record](ui-acceptance.md#independent-desktop-review-record) so
another engineer can verify the result. Run the
[Playwright browser suite](ui-acceptance.md#browser-acceptance) separately;
automated success is not a substitute for this independent trial.
Local-ledger exact lookup and application tracking require their own source:
the fixture demo cannot prove finalized readback or authenticated status
history. Keep those paths **not run** rather than inventing a result.

A mobile-device target and another task-based demo are deferred to
[issue #265](https://github.com/midnightntwrk/midnight-trust-registry/issues/265).
The existing responsive Playwright checks remain regressions, not mobile
acceptance. The scripted demo above remains an optional fixture reference path,
not a gate for this desktop UI closeout.

## Qualify a self-hosted installation

Installation may use the network. After installation, the dedicated local
ledger and actor runtime must work with external egress denied. Use one
isolated Docker project, one private setup directory, and one exact-source
install bundle. Do not reuse a sibling project's containers, volumes, wallet,
or saved receipts.

1. Follow the [standalone first-run guide](standalone.md) to verify the
   source-matched bundle, start the dedicated bridge, and collect the node's
   **untrusted** genesis candidate. The unattended path stops before signing
   or deployment.
2. Have a human independently review the chain specification and exact
   approval bytes, then sign with their own key. Separately approve the
   release maintenance threshold, public keys, and custody roles. The
   development 1-of-3 smoke roster does not qualify a release. The genesis
   reviewer may be different from the governance reviewer: the signed
   committee approval must name the exact genesis-approval digest. The
   committee, deployment approval, and API plan must use the pinned
   governance reviewer fingerprint. Import both public keys into the private
   verification keyring when the reviewers differ. Adding a key to that
   keyring alone does not authorize a substituted genesis approval or rotate
   the governance reviewer; a later rotation needs an explicit reviewed
   protocol change.
3. Deploy once through the approved provider, independently authenticate
   finalized constructor and verifier-key readback, transition to the
   approved committee, and sign a deployment-bound current API plan. Do not
   retry an ambiguous submission without reconciliation.
4. Only then run the [real actor acceptance procedure](end-to-end-testing.md#run-and-record-the-real-use-case)
   and the [operator acceptance record](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/guide/standalone-local-journey.md#operator-acceptance-record).

Before any actor run, check the selected candidate. Replace the paths with
private absolute paths; the source SHA must be the full commit used to build
the bundle:

```sh
SOURCE_SHA="$(git rev-parse HEAD)"
node scripts/check-standalone-install.mjs "$INSTALL" "$SOURCE_SHA"
node scripts/standalone-setup-wizard.mjs status "$SETUP"
node scripts/check-standalone-journey-prerequisites.mjs "$SETUP" "$SOURCE_SHA"
```

Prerequisite exit code **2** means stop and follow `nextSafeAction`; exit code
**1** means the input could not be checked. Exit code **0** verifies only
wizard-recorded prerequisites. It does not prove authenticated finality, a
live actor transaction, offline egress denial, or release readiness. Never
substitute an older setup SHA to force a pass.

The packaged local-ledger API currently serves **current reads only** and
does not construct production governed-write ports. A reviewed embedding
host, authenticated finality, and a VC-owned live status-authority adapter
are still needed for deployed issuer/verifier/auditor/maintainer journeys.
The [actor-host handoff](standalone-actor-host.md) identifies those contracts;
injected test providers and simulator receipts are not acceptable evidence.
Restart/restore, full actor egress denial, and independent human security
review remain separate acceptance gates. Promotion PR #198 merged the milestone
code into `develop`; it did not qualify a local release candidate or close
these gates.

## What to share with another adopter

Share the pinned source and install inventory digest, network profile,
approved genesis and committee **public** information, deployment address,
signed current API-plan digest, and a redacted acceptance record. Keep seeds,
private keys, wallet material, and raw personal evidence out of the repo and
chat. Record every case as passed, failed, or not run; do not replace a
missing deployed case with a demo result.
