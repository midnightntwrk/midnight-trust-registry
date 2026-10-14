# Quality proving-key cache

The Quality job previously ran the full `pnpm run build` for every PR. On run
`38587142287`, `Build all workspaces` consumed about 56 of the job's 57 minutes;
Turbo reported no task-cache hits and Compact regenerated keys for 66 circuits.
The PR did not change Compact inputs.

Quality now runs `pnpm run build:light`, which compiles the contract and emits
ZKIR without generating prover/verifier keys. For a Compact source, compiler-pin,
or contract build-input change, it then runs `scripts/proving-key-cache.mjs`.
The script matches each key pair to the SHA-256 of its ZKIR and to the pinned
Compact and `zkir` versions. It regenerates missing, changed, or corrupt pairs;
an empty ZKIR directory fails the job. Generated keys are copied into the
contract distribution and cached under the compiler pin and runner platform.

The cache is an optimization, not an authorization source. Its manifest hashes
detect accidental damage or mismatches, but they do not independently prove
that a restored key was generated from the ZKIR. The first eligible run without
a matching cache still pays the full proving cost. GitHub scopes PR caches, so
the milestone branch push seeds a base-branch cache that later PRs can restore;
one PR's cache is not generally available to a sibling PR.

Validation:

```bash
pnpm run check:compact-version
pnpm run build:light
./run.sh --light
pnpm audit --audit-level low
```

Monitor the `Verify and complete ZKIR-derived proving keys` log for its reused
and generated counts. If a contract change alters most ZKIRs, expect a cold
run near the old 56-minute baseline; ordinary TS/docs PRs should avoid that
cost. A future scheduled cold build should independently regenerate all keys
and compare hashes before treating cached key provenance as verified.
