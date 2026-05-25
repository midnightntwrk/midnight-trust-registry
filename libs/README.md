# Local Identity Package Tarballs

This directory contains packed external Midnight identity packages that
`midnight-trust-registry` depends on locally until those packages are published.

Current rule:

- do not vendor source directories from other `midnight-*` repositories
- keep cross-repository dependencies as `.tgz` package artifacts
- refresh tarballs only through the workspace-root sync wrapper
- keep package manifests pointed at tarballs, not copied source trees

Layout:

- DID tarballs live under `libs/midnight-did/`
- VC tarballs live under `tooling/vendor/midnight-verifiable-credentials/`

Refresh from the workspace root with:

```bash
./scripts/sync-package-tarballs.sh --source did --destination midnight-trust-registry
./scripts/sync-package-tarballs.sh --source vc --destination midnight-trust-registry
```
