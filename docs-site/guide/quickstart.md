# Quickstart and local demo

This is a **local reference journey**. Its operator workspace and Compact simulator do not constitute a live network deployment.

For a self-hosted installation, start with the
[standalone first-run guide](standalone.md) instead. Its ledger-bridge smoke is
also not an end-to-end acceptance run: the deployed actor cases and their
required evidence are listed in the
[operator acceptance record](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-local-journey.md#operator-acceptance-record).

## Prerequisites

- Node.js 24 and pnpm 10.34.1 or later.
- The pinned Midnight Compact compiler for full contract builds. `nix develop` supplies the repository toolchain.
- A fresh checkout with `pnpm install --frozen-lockfile`.

```bash
pnpm install --frozen-lockfile
./run.sh --light
pnpm run demo:governed
```

The governed demo exercises the local simulator, policy-bound maintainers, and authorization transitions. Its `proposalDenial` report shows that a pending duplicate scope is blocked, a one-signer archive fails, a 2-of-3 archive preserves the historical record without granting trust, and a fresh application ID may reuse the scope. Its issuer and verifier VC journeys build and check a decision-evidence claim at the demo HTTP API, independently check the `client-required` response at the consumer, obtain a governed VC authority proof, and install that proof in a compiled VC consumer. After suspension and revocation, fresh simulator ledger reads make the API return `503` rather than serve the old active claim; the consumer also refuses it. This is a cross-surface reference flow, **not** network finality or production key custody. The packaged API does not enable this optional route without an embedding host's finalized evidence source. The additional role-specific demos exercise signed membership journeys:

```bash
pnpm run test:e2e:demo

# Or run each role separately:
pnpm run demo:signed-issuer
pnpm run demo:signed-verifier
pnpm run demo:signed-auditor
pnpm run demo:signed-maintainer
```

`test:e2e:demo` checks the prebuilt Compact source, safely rebuilds its
TypeScript/UI dependencies, then starts the fixture API and both served UIs
on ephemeral loopback ports. Quality CI runs the four journeys together with
`pnpm run demo:membership:smoke` after the package build; that step does not
regenerate proving keys. Neither command exercises a deployed local ledger.
With Google Chrome installed, `pnpm run test:e2e:demo:browser` follows the
demo checks with the applicant and admin Playwright journeys using the same
built assets. It does not run `build:light` or qualify standalone deployment.
The individual demo aliases and `pnpm run test:browser` also use the safe
prebuilt package build. They require a source-matched Compact output prepared
earlier; none silently regenerates or removes proving artifacts.

Each signed journey starts a fresh private operator-workspace file and serves
its API reads from that file. Governed Compact epoch publication persists the
new simulator projection; unsigned fixture mutation routes remain disabled.
The demo acquires the workspace lock before the Compact epoch action and
checks that another process receives 409 without advancing that action.
It materializes per-grant historical evidence before preparing the external
epoch signature. The projector rejects any later evidence generation that
would replace the signed registry epoch as Compact's current epoch, before
the projection can advance governance.
After the lifecycle, a separate Node process opens the persisted workspace
and serves the final epoch. For issuer, verifier, and auditor, it also recovers
the historical active decision and the final revoked decision from public HTTP
queries without sharing the original simulator process.
The file adapter provides local durability and locking, not network finality
or atomic admission-plus-governance execution.

The issuer, verifier, and auditor demos also query the native timestamped
evidence API after suspension and revocation. Each response is checked against
the simulator's separately read epoch record and maintainer key; a substituted
resource or epoch root is rejected. An old active decision stays provable at
its original instant, but does not imply current authorization. Lifecycle
actions can replace the current record's `evidenceHash`, while an archived
bundle retains its original evidence commitment. The simulator anchor in this
demo is not a production finalized-ledger reader.
The governed demo performs the analogous historical proof check for external
recognition after suspension and revocation, including wrong-registry and
wrong-root rejection. Recognition still does not confer local issuer trust.

For the cross-surface local API and UI smoke, use `pnpm run demo:smoke`. The repository's [demo guide](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/guide/demo-and-release.md) explains its fixture and process model. `pnpm run integration` runs the broader simulator and API integration suite. The demos may take longer than `--light` because Compact artifacts and proving material can be generated.

## Local API and applications

The packaged API can serve read-only query data from a saved operator workspace. The root scripts also offer local UI demo servers:

```bash
pnpm run demo:prepare
pnpm run demo:serve:api
pnpm run demo:serve:admin-console
pnpm run demo:serve:applicant-portal
```

`demo:serve:api` deliberately passes `--unsafe-demo-mutations`. That switch is accepted only on loopback and makes unsigned workspace replay available for UI demonstrations. **Never use it for real trust decisions.** The packaged CLI does not inject production DID resolution or Compact-backed governed-action ports; those routes return `503` unless an embedding host supplies them. See [API safety](../api/index.md).

For a signed applicant walkthrough, use the isolated fixture host instead:
`node scripts/demo-auditor-admission.mjs serve 4400 issuer`, replacing `issuer`
with `verifier`, `auditor`, or `maintainer` as needed. The applicant portal shows structured
role-specific fields and a digest to sign outside the browser. The terminal
prints the matching fixture draft and one-use VP command. A successful run
registers a pending application and redacted eligibility evidence; it does
not approve or activate membership. The signer, clock, DID resolver, and VP
are local fixtures, not production trust or Midnight finality.
The maintainer form derives its exact registry scope from the API's current
context rather than an applicant-entered registry ID.

With Google Chrome installed, `pnpm run test:browser` builds and exercises
the issuer, verifier, auditor, and maintainer forms in a real browser against
the authenticated loopback admission host. The browser test rejects a forged
applicant signature, accepts the valid fixture signature, and submits a
challenge-bound VP without rendering raw presentation data. It does not
establish production identity, status-root finality, or network settlement.

## Read a decision

With the local API running, `GET /health`, `GET /v1/registry`, and `GET /v1/epochs/current` show the loaded snapshot. A scoped authorization query must use a canonical composite resource ID; a bare profile name is not enough. Query output is only informational until the caller verifies the registry anchor, policy, signatures, epoch, and inclusion evidence independently.
