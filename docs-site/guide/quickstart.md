# Quickstart and local demo

This is a **local reference journey**. Its operator workspace and Compact simulator do not constitute a live network deployment.

## Prerequisites

- Node.js 24 and pnpm 10.34.1 or later.
- The pinned Midnight Compact compiler for full contract builds. `nix develop` supplies the repository toolchain.
- A fresh checkout with `pnpm install --frozen-lockfile`.

```bash
pnpm install --frozen-lockfile
./run.sh --light
pnpm run demo:governed
```

The governed demo exercises the local simulator, policy-bound maintainers, and authorization transitions. Its issuer and verifier VC journeys build and check a decision-evidence claim at the demo HTTP API, independently check the `client-required` response at the consumer, obtain a governed VC authority proof, and install that proof in a compiled VC consumer. After suspension and revocation, fresh simulator ledger reads make the API return `503` rather than serve the old active claim; the consumer also refuses it. This is a cross-surface reference flow, **not** network finality or production key custody. The packaged API does not enable this optional route without an embedding host's finalized evidence source. The additional role-specific demos exercise signed membership journeys:

```bash
pnpm run demo:signed-issuer
pnpm run demo:signed-verifier
pnpm run demo:signed-auditor
pnpm run demo:signed-maintainer
```

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

## Read a decision

With the local API running, `GET /health`, `GET /v1/registry`, and `GET /v1/epochs/current` show the loaded snapshot. A scoped authorization query must use a canonical composite resource ID; a bare profile name is not enough. Query output is only informational until the caller verifies the registry anchor, policy, signatures, epoch, and inclusion evidence independently.
