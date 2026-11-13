# Dependency update policy

Trust Registry uses the pinned pnpm version in `package.json` and resolves new
dependencies with these workspace policies:

The root `packageManager` pin selects the reviewed development/CI toolchain.
Published workspace packages retain `engines.pnpm: >=10`; a toolchain security
update must not silently narrow their consumer compatibility.

- `blockExoticSubdeps: true` rejects transitive Git, URL, and other exotic
  sources outside the configured registries.
- `trustPolicy: no-downgrade` rejects a version whose publication trust is
  weaker than an earlier version.
- `minimumReleaseAge: 10080` waits seven days before resolving a newly
  published version. A frozen install of an already reviewed lockfile remains
  reproducible.

For an urgent security update, propose an exact `package@version` entry in
`minimumReleaseAgeExclude` in a reviewed PR. Link the advisory, identify the
release owner, explain why waiting is unsafe, and record when the exception
will be removed. Do not exclude an entire package family or disable the
workspace policy. A `trustPolicyExclude` entry needs separate evidence for the
exact artifact and a documented owner; an age exception does not waive trust
checks. Re-run frozen install, audit, package tests, and applicable CI after
any exception or dependency change.

This pnpm resolution policy is separate from npm CLI publication. Do not set a
global npm `min-release-age` for the release job: its smoke test must install
the exact prerelease immediately after publication. npm publication still
requires the protected workflow and release approval described in #271.
