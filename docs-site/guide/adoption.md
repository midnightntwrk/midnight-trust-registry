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
on a real ledger. If Chrome is installed, run `pnpm exec playwright test` to
exercise the applicant and admin flows in a real browser. Report the browser
lane as not run if Chrome is unavailable.

`./run.sh --light` removes generated Compact outputs. Never run it in a
checkout holding full proving keys, a verified install bundle, or private
approval evidence. In such a checkout, use `pnpm run integration:prebuilt`
for the existing prebuilt simulator integration lane instead; it is not a
standalone deployment test. See the [demo details](quickstart.md) and
[test boundaries](end-to-end-testing.md).

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
   development 1-of-3 smoke roster does not qualify a release.
3. Deploy once through the approved provider, independently authenticate
   finalized constructor and verifier-key readback, transition to the
   approved committee, and sign a deployment-bound current API plan. Do not
   retry an ambiguous submission without reconciliation.
4. Only then run the [real actor acceptance procedure](end-to-end-testing.md#run-and-record-the-real-use-case)
   and the [operator acceptance record](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-local-journey.md#operator-acceptance-record).

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
review remain separate acceptance gates. Keep the 0.1.0 promotion draft
unmerged until the local-only scope and all release gates are explicitly met.

## What to share with another adopter

Share the pinned source and install inventory digest, network profile,
approved genesis and committee **public** information, deployment address,
signed current API-plan digest, and a redacted acceptance record. Keep seeds,
private keys, wallet material, and raw personal evidence out of the repo and
chat. Record every case as passed, failed, or not run; do not replace a
missing deployed case with a demo result.
