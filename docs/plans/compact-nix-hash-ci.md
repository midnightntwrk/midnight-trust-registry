# Compact Nix fetch-hash validation

Issue: #95. This slice adds a path-scoped Linux canary; it does not close the
issue or make the new check a protected-branch requirement by itself.

When `.compact-version`, either Compact Nix expression, or their flake wiring
changes, `Compact Nix Hash` builds `.#compact-toolchain` and
`.#compact-midnight` on x86_64 Linux. It checks the installed `compactc`
version against `.compact-version` and runs the additional `compact` binary.
The version check catches an old toolchain archive reused under an unchanged
hash; an uncached stale hash causes Nix to fail the fetch. For each package,
a second build in a temporary copied flake replaces only the native-platform
hash with a known-wrong hash and MUST fail with that exact fixed-output hash
mismatch. The temporary copy leaves the repository and real Nix expressions
untouched. The workflow also supports a manual run. Its path filter avoids
adding Nix installation and download time to ordinary PRs.

To upgrade the compiler toolchain, update `.compact-version` and both platform
hashes in `nix/packages/compact-toolchain.nix` from the verified Compact
release. `nix/packages/compact-midnight.nix` has its own version and hashes;
verify those independently when changing that package.
Treat a hash mismatch as a release-artifact identity failure, not a flaky
fetch to retry blindly. Verify the release URL and expected archive before
recording Nix's reported hash. Do not set a fake or empty hash in the actual
expression. Run `./run.sh --light` and this Linux workflow on the candidate
PR. On a supported aarch64-darwin Nix host, also run
`nix build --no-link .#compact-toolchain` and
`nix build --no-link .#compact-midnight`; compare the toolchain's
`bin/compactc --version` with `.compact-version`. Linux CI cannot validate
the Darwin hashes.

This is an advisory path-scoped workflow until an always-present required
check incorporates the result or branch protection is changed without
blocking unrelated PRs. Do not claim that a stale hash is merge-blocking on
`milestone-0.1.0` solely because this workflow exists. The first real
pin-change PR and a clean Darwin build remain the completion evidence for
#95. Local Darwin validation uses the available Nix installation; Linux
validation remains CI evidence for this slice.
