# Vendored Identity Libraries

This directory contains the local copies of external Midnight identity package
sources that `midnight-trust-registry` depends on directly.

Current rule:

- sync only the packages required by the TR workspace manifests
- group synced packages by source repo:
  - `libs/midnight-did/...`
  - `libs/midnight-verifiable-credentials/...`
- commit the synced package sources and built `dist/` outputs required for local
  installs and CI
- import Compact sources from `libs/` instead of from `node_modules/`

Refresh from the sibling repos with:

```bash
./upgrade-libs.sh --destination .
```
