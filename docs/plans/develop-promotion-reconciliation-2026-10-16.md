# Develop-to-milestone ancestry reconciliation

Status: proposed integration record, not a release declaration

The `milestone-0.1.0` branch contains the implementation intended for the
draft promotion PR into `develop`. At the reconciliation point, `develop` had
three commits absent from the milestone branch. Directly merging the branches
produced conflicts across documentation, workflows, dependencies, and tests.

| Develop-only commit | Cherry-pick audit against the milestone tree |
| --- | --- |
| `f3f8360` (#80, reference profile) | Its cherry-pick was empty after choosing the milestone versions of conflicting documentation. The milestone already contains the reference profile and issue plan. |
| `2b86982` (#87, Turbo cache and audit) | Its only surviving patch duplicated Turbo restore/save steps and the `turbo-cache` workflow step ID. The milestone has a newer Compact-version-aware cache flow; its existing dependency audit passes. The obsolete patch was not retained. |
| `71242ae` (#89, published DID/VC packages) | Its cherry-pick was empty after choosing the milestone versions of conflicting files. The milestone already consumes published DID 0.7.0 and VC 0.2.0 packages, without the old VC tarballs. |

A signed, DCO merge records `develop` as the second parent while preserving the
milestone tree. This is an **audited ancestry reconciliation**, not a blanket
claim that every release criterion is complete. The only file change in the
reconciliation PR is this record. The milestone-to-`develop` PR must still pass
its exact-head CI and review gates; the open 0.1.0 acceptance issues remain
open until they have their own implementation evidence.

Local validation on the reconciliation branch before this documentation change:
`./run.sh --light` passed and `pnpm audit --audit-level low` reported no known
vulnerabilities. The post-documentation light run is part of the PR gate.
