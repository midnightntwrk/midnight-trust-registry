# Identity Dependencies

Trust Registry consumes published Midnight DID and VC packages from npm at
the versions pinned in `package.json`, `pnpm-workspace.yaml`, and
`pnpm-lock.yaml`. No identity package tarballs or sibling-repository source
trees are vendored in this repository.

Use `pnpm run refresh:identity-dependencies` to update the coordinated DID
and VC package families, then run the light and integration gates before
publishing the change.
