# Compact Nix fetch-hash validation

Issue: #95. This slice adds a path-scoped Linux canary; it does not close the
issue or make the new check a protected-branch requirement by itself.

When `.compact-version`, the Compact Nix expression, or their flake wiring
changes, `Compact Nix Hash` builds `.#compact-toolchain` on x86_64 Linux and
checks the installed `compactc --version` against `.compact-version`. The
version check catches an old fixed-output archive reused under an unchanged
hash; an uncached stale hash causes Nix to fail the fetch. A second build in a
temporary copied flake replaces only the Linux hash with a known-wrong hash
and MUST fail specifically with a hash mismatch. The temporary copy leaves the
repository and real Nix expression untouched. The workflow also supports a
manual run. Its path filter avoids adding Nix installation and download time
to ordinary PRs.

To upgrade the compiler, update `.compact-version` and both platform hashes
in `nix/packages/compact-toolchain.nix` from the verified Compact release.
Treat a hash mismatch as a release-artifact identity failure, not a flaky
fetch to retry blindly. Verify the release URL and expected archive before
recording Nix's reported hash. Do not set a fake or empty hash in the actual
expression. Run `./run.sh --light` and this Linux workflow on the candidate
PR. On a supported aarch64-darwin Nix host, also run
`nix build --no-link .#compact-toolchain` and compare the resulting
`bin/compactc --version` with `.compact-version`; Linux CI cannot validate the
Darwin hash.

This is an advisory path-scoped workflow until an always-present required
check incorporates the result or branch protection is changed without
blocking unrelated PRs. Do not claim that a stale hash is merge-blocking on
`milestone-0.1.0` solely because this workflow exists. The first real
pin-change PR and a clean Darwin build remain the completion evidence for
#95. No Nix binary is installed in the current macOS local workspace, so the
Linux build and deliberate mismatch are CI-only validation for this slice.
