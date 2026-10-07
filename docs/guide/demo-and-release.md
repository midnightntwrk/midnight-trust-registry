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
- starts both UI servers on ephemeral loopback ports and fetches their HTML,
  recursively emitted JavaScript modules, and CSS assets; missing relative
  imports fail before HTTP probing, while empty type-only modules are allowed

Each default run uses a unique temporary directory under
`artifacts/trust-registry/demo-smoke/`, so retained or interrupted runs do not
block later smoke runs. Pass `--keep-artifacts` to retain the generated files;
the command prints their location. An explicit `--workspace` path is never
overwritten, and cleanup removes only files created by that run.
An interrupted default run can leave a `run-*` directory under
`artifacts/trust-registry/demo-smoke/`; inspect those directories before
manually removing them. The smoke runner never recursively removes a
user-provided `--workspace` directory. If shutdown needs SIGKILL, the command
warns but still succeeds when the child exits. An unresponsive child or failed
cleanup fails the command and reports the original failure and any retained
artifact path.

The main and milestone CI workflows run the same smoke command after
`./run.sh --light`, so missing build outputs or broken local startup fail from a
clean checkout without repeating the full proving build. On failure, the smoke
command includes captured API and UI process output.

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

Those packages remain local-only while their public packaging and deployment
policy is finalized. They are still packed into `artifacts/npm/` for downstream
workspace use and smoke-tested there; DID and VC dependencies come from npm.

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

- `@midnight-ntwrk/midnight-did@0.7.0`
- `@midnight-ntwrk/midnight-did-contract@0.7.0`
- `@midnight-ntwrk/midnight-did-domain@0.7.0`
- `@midnight-ntwrk/midnight-did-jubjub-schnorr@0.7.0`

Current VC baseline is `@midnight-ntwrk/credential-compact@0.2.0` and
`@midnight-ntwrk/credential-did-midnight@0.2.0` from npm. The retired private
VC/status package tarballs are not supported. VC `0.2.0` does not include the
old status-helper API; live status-registry evidence needs a separate adapter.
Issuer evidence now includes a governed status-policy commitment in its signed
authorization leaf and a client-verified preimage naming the accepted registry
and authority method. The legacy `referencedStatusRegistryId` hint is rejected
for issuer decisions. This does not prove a credential is unrevoked: a separate
adapter must verify status-authority DID state and a fresh authenticated VC
status proof before consumers accept a non-revocation claim.

Refresh the published DID and VC versions with validation:

```bash
pnpm run refresh:identity-dependencies -- --did-version 0.7.0 --vc-version 0.2.0 --validate light
```

Useful variants:

```bash
pnpm run refresh:identity-dependencies -- --did-version latest --skip-vc --validate none
pnpm run refresh:identity-dependencies -- --skip-did --vc-version 0.2.0 --validate integration
```
