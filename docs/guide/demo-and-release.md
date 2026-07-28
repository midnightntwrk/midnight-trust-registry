# Demo And Release Guide

Updated: 2026-07-24

This guide is the public operator walkthrough for the local demo path, package
artifact boundaries, and the manual release automation currently checked into
`midnight-trust-registry`.

## Demo Workflow

Prepare a mutable operator workspace:

```bash
pnpm run demo:prepare
```

Prepare a deterministic read-only snapshot for fixture-driven demos:

```bash
pnpm run demo:prepare:snapshot
```

Start the local surfaces in separate terminals:

```bash
pnpm run demo:serve:api
pnpm run demo:serve:admin-console
pnpm run demo:serve:applicant-portal
```

Default local endpoints:

- API: `http://127.0.0.1:4400`
- Admin console: `http://127.0.0.1:4173`
- Applicant portal: `http://127.0.0.1:4175`

The documented demo lane is smoke-tested with:

```bash
pnpm run demo:smoke
```

That command:

- builds the CLI, API, and local UI packages
- seeds a workspace and a deterministic snapshot
- starts the API on loopback
- submits and approves an issuer application
- publishes an epoch
- verifies that the resulting trust state is queryable

The main CI workflow also runs the same smoke command after `./run.sh --light`
so demo drift is caught from a clean checkout.

## Artifact Boundaries

The repository currently distinguishes between two artifact classes.

Local artifact packages:

- `@midnight-ntwrk/trust-registry-contract`
- `@midnight-ntwrk/trust-registry-domain`
- `@midnight-ntwrk/trust-registry-client`
- `@midnight-ntwrk/trust-registry-integration`
- `@midnight-ntwrk/trust-registry-cli`
- `@midnight-ntwrk/trust-registry-api`
- `@midnight-ntwrk/trust-registry-trqp-adapter`
- `@midnight-ntwrk/trust-registry-openid-federation-adapter`

Remotely publishable core packages:

- `@midnight-ntwrk/trust-registry-contract`
- `@midnight-ntwrk/trust-registry-domain`
- `@midnight-ntwrk/trust-registry-client`
- `@midnight-ntwrk/trust-registry-trqp-adapter`
- `@midnight-ntwrk/trust-registry-openid-federation-adapter`

Local-only artifact packages for now:

- `@midnight-ntwrk/trust-registry-integration`
- `@midnight-ntwrk/trust-registry-cli`
- `@midnight-ntwrk/trust-registry-api`

Those packages remain local-only because they still rely on unpublished or
vendored VC inputs for the simulator-backed demo path. They are still packed
into `artifacts/npm/` for downstream workspace use and smoke-tested there, but
they are intentionally excluded from the public npm publish workflow until the
dependency story is fully registry-safe.

Pack and validate local artifact tarballs:

```bash
pnpm run artifacts:pack
pnpm run packages:check-contents
pnpm run packed-artifacts:smoke
```

## Release Workflow

The repo currently exposes two manual GitHub Actions workflows:

- `Publish Packages`
- `Published Package Smoke`

`Publish Packages` performs the following sequence:

1. stamps a release version across the root and workspace manifests
2. validates manifest and package-content expectations
3. builds the repository
4. packs release tarballs and smoke-tests them locally
5. publishes the remotely publishable core packages
6. smoke-tests the published packages from the configured registry

The publish workflow only runs from the `develop` branch and pauses at the
protected `npm-publish` environment. Configure required reviewers and the
`NPM_TOKEN` secret on that environment before using the workflow in a public
repository.

`Published Package Smoke` reruns only the final published-package import smoke
for a specified version.

Local helpers used by the workflow:

```bash
node scripts/release-set-version.mjs --version 0.1.0-rc2
pnpm run published-artifacts:smoke -- --tarball-dir artifacts/npm-release
```

The publish workflow expects `NPM_TOKEN` to be configured as a repository
secret. The default registry is `https://registry.npmjs.org`.

## Dependency Refresh

Current supported DID baseline:

- `@midnight-ntwrk/midnight-did@0.5.0-rc2`
- `@midnight-ntwrk/midnight-did-contract@0.5.0-rc2`
- `@midnight-ntwrk/midnight-did-domain@0.5.0-rc2`
- `@midnight-ntwrk/midnight-did-jubjub-schnorr@0.5.0-rc2`

VC inputs are still consumed from vendored tarballs under
`tooling/vendor/midnight-verifiable-credentials/`.

Refresh the published DID version and the vendored VC tarballs with validation:

```bash
pnpm run refresh:identity-dependencies -- --did-version 0.5.0-rc2 --validate light
```

Useful variants:

```bash
pnpm run refresh:identity-dependencies -- --did-version latest --skip-vc --validate none
pnpm run refresh:identity-dependencies -- --skip-did --validate integration
```

The VC refresh step relies on the workspace-root
`scripts/sync-package-tarballs.sh` helper, so the full refresh path is intended
to run from the `midnight-identity-workspace` checkout.
