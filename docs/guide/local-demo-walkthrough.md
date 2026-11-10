# Local Trust Registry demo

This walkthrough is a **fixture demonstration** on loopback. It shows the
operator and applicant surfaces and exercises successful registry journeys,
but it does not deploy a contract to a Midnight node or qualify the standalone
release candidate. Use the [standalone local journey](standalone-local-journey.md)
for deployed acceptance evidence.

## Run the automated journeys

From a clean, disposable checkout of `develop`, with Node.js 24, pnpm, and the
repository-pinned Compact compiler installed:

```sh
pnpm install --frozen-lockfile
pnpm run check:compact-installed
pnpm run build:light
pnpm run test:e2e:demo:browser
node scripts/demo-governed-registry.mjs
node scripts/demo-signed-journey.mjs
node scripts/demo-auditor-admission.mjs smoke
```

`build:light` replaces generated `dist` outputs. Never run it in a checkout
holding irreplaceable Compact keys, pinned install bundles, or private setup
evidence. The browser command runs signed issuer, verifier, auditor, and
maintainer membership journeys, the API/UI smoke, and Playwright browser
cases. The governed command covers 2-of-3 proposals, recognition, epoch
publication, policy change, and current/historical trust decisions in the
Compact simulator. The remaining commands cover signed mutation and auditor
admission. Their fixture keys, status decisions, and simulated finality are
not a live VC status authority or deployed-ledger proof.

## Leave the demo open for a walkthrough

In a fresh checkout, initialize the mutable workspace and a separate read-only
snapshot once:

```sh
pnpm run demo:prepare
pnpm run demo:prepare:snapshot
```

Those commands refuse to overwrite existing output.
The current demo uses `artifacts/trust-registry/midnight-demo-workspace.json`
and `midnight-demo-snapshot.json`. Older fixture files are not renamed or
rewritten because their IDs and evidence refer to the original workspace.
Start these services in three terminals:

```sh
pnpm run demo:serve:api
pnpm run demo:serve:admin-console
pnpm run demo:serve:applicant-portal
```

Open the [admin console](http://127.0.0.1:4173) and
[applicant portal](http://127.0.0.1:4175). The fixture API is at
`http://127.0.0.1:4400`; `GET /health` must report `sourceMode: "workspace"`.
The API is started with `--unsafe-demo-mutations` only for this loopback demo.
Never expose it to an untrusted network or use its state as release evidence.

To populate the board with one active issuer, submit and advance a fixture
application, then publish an epoch:

```sh
curl -fsS -X POST -H 'content-type: application/json' \
  --data '{"target":"issuer","label":"local-demo-issuer"}' \
  http://127.0.0.1:4400/v1/applications
curl -fsS -X POST \
  http://127.0.0.1:4400/v1/applications/issuer/auth:issuer:local-demo-issuer:v1/approve
curl -fsS -X POST \
  http://127.0.0.1:4400/v1/applications/issuer/auth:issuer:local-demo-issuer:v1/activate
curl -fsS -X POST -H 'content-type: application/json' \
  --data '{"label":"local-demo-active"}' \
  http://127.0.0.1:4400/v1/epochs/publish
curl -fsS 'http://127.0.0.1:4400/v1/authorizations/issuer?status=active'
```

The final response should have `total: 1` and an active authorization. Refresh
the admin console to see the new epoch and issuer. This direct HTTP path is a
fixture shortcut; it does not exercise the signed governed proposal workflow.
Use the automated signed and governed journeys above for that behavior.

## What this does not prove

The packaged local-ledger CLI is currently read-only. This walkthrough does
not prove a signed genesis approval, authenticated finalized deployment and
readback, approved maintenance transition, live VC-owned status authority,
egress-denied deployed actor journeys, deployed restart/restore, or independent
human security review. Keep those as separate standalone qualification gates.
