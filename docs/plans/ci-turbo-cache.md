# Hosted Turbo cache baseline

The `Quality` workflow uses GitHub's cache service for Turbo task artifacts.
This is a local-cache transport, not a remote Turbo service, and it requires no
new secrets. `CI` runs different `build:light` and `test:light` task hashes, so
it does not download the Quality archive.

- Quality sets `TURBO_CACHE_DIR=.turbo/cache` so restore and Turbo use the same
  directory. The directory is ignored by Git. Turbo 2.10 bounds the local
  archive to 2 GB and seven days before it is republished.
- Cache keys include runner OS, Compact compiler version, the lockfile,
  `turbo.json`, and `.nvmrc`, but not the commit SHA. The first trusted push
  seeds one immutable archive per build-input version; Turbo still hashes task
  inputs before replaying outputs. Bump the cache version deliberately when
  the baseline becomes stale rather than uploading a new archive every push.
- PR jobs restore only. `Quality` publishes only after build and typecheck on
  trusted `push` runs. Untrusted PR code cannot publish a cache for the branch
  baseline.
- The first trusted push after this change is a cold-cache seed. Cache hit rate,
  archive size, upload/download time, and full-build P50/P90 need measurement
  before claiming a speedup.

This does not fix the docs-only full-build routing problem tracked in [#84](https://github.com/midnightntwrk/midnight-trust-registry/issues/84).
The audit advisories that made the 2026-10-04 `Quality` job red are tracked in
[#86](https://github.com/midnightntwrk/midnight-trust-registry/issues/86); the
audit threshold remains unchanged.

References: [Turborepo GitHub Actions caching](https://turborepo.dev/docs/guides/ci-vendors/github-actions),
[Turborepo cache directory](https://turborepo.dev/docs/reference/configuration),
[Turborepo 2.10 cache eviction](https://turborepo.dev/blog/2-10),
and [GitHub dependency caching security](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
