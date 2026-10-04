# Hosted Turbo cache baseline

The `Quality` and `CI` workflows now use GitHub's cache service for Turbo task
artifacts. This is a local-cache transport, not a remote Turbo service and it
requires no new secrets.

- Both workflows set `TURBO_CACHE_DIR=.turbo/cache` so restore and Turbo use the
  same directory. The directory is ignored by Git.
- Cache keys include runner OS, Compact compiler version, the lockfile,
  `turbo.json`, `.nvmrc`, and the commit SHA. Restore keys reuse a compatible
  earlier artifact when only source files change; Turbo still hashes task inputs
  before replaying outputs.
- PR jobs restore only. `Quality` publishes only after build and typecheck on
  trusted `push` runs. Untrusted PR code cannot publish a cache for the branch
  baseline. `CI` restores but does not publish, avoiding duplicate writers.
- The first trusted push after this change is a cold-cache seed. Cache hit rate,
  archive size, upload/download time, and full-build P50/P90 need measurement
  before claiming a speedup.

This does not fix the docs-only full-build routing problem tracked in [#84](https://github.com/midnightntwrk/midnight-trust-registry/issues/84).
The audit advisories that made the 2026-10-04 `Quality` job red are tracked in
[#86](https://github.com/midnightntwrk/midnight-trust-registry/issues/86); the
audit threshold remains unchanged.

References: [Turborepo GitHub Actions caching](https://turborepo.dev/docs/guides/ci-vendors/github-actions),
[Turborepo cache directory](https://turborepo.dev/docs/reference/configuration),
and [GitHub dependency caching security](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
