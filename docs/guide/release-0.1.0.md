# Midnight Trust Registry 0.1.0 release scope

Status: **candidate source for a non-production local/offline release**. This
page defines the release boundary; it is not an announcement that a final
bundle has been verified or published.

## Delivered in source

- A Compact Trust Registry contract with governed maintainer, issuer,
  verifier, auditor, recognition, evidence-verifier, and epoch actions. The
  build contains 66 proof circuits.
- TypeScript domain and client packages, TRQP and OpenID Federation adapters,
  and local CLI/API integration surfaces. The applicant portal and admin
  console provide role-oriented reference flows.
- A standalone local/offline installer with a pinned Midnight Ledger 8 node,
  indexer, and proof server; source-bound package and image inventories;
  loopback-only runtime setup; and private per-installation genesis review.
- A keyless contract distribution path containing `.zkir` and `.bzkir`
  circuits, with an authenticated manifest of expected prover/verifier hashes.
  Prover and verifier key bytes are generated and checked on the operator host,
  not shipped in the public bundle.
- Simulator, package-consumer, API/UI, Playwright, and predeployment
  standalone smoke tests, plus architecture, adoption, and operator guides.
  These are useful developer checks, not deployed-ledger acceptance evidence.

The GitHub release must provide the exact signed source revision, bundle
inventory and asset SHA-256, supported platform, and limitations. Five core
package tarballs may be attached for review, but npm publication and GHCR
application-image publication require their separate protected workflows.

## Supported environment

The first distribution targets one **self-hosted local/offline Ledger 8**
installation on the platform named in its verified bundle. A node-reported
genesis hash is installation-specific input, not a universal constant or a
signature. The setup wizard must not cross its unsigned genesis gate on the
basis of a configured hash alone.

Preview, Preprod, Mainnet, Ledger 9 migration, Kubernetes/Helm qualification,
and mobile acceptance are out of scope. The release does not imply those
networks or platforms have been tested.

## Not production ready

No final source-matched installation has yet completed independently signed
genesis approval, authenticated finalized contract deployment/readback,
approved maintenance transition, VC-owned live status integration,
egress-denied actor journeys, deployed restart/restore, audited ambiguous
proposal recovery, or independent human security review. Fixture and mocked
provider tests cannot substitute for those observations. Do not use this
release as a production trust authority or present it as a deployable
end-to-end qualification.

The exact remaining work is tracked in
[#219](https://github.com/midnightntwrk/midnight-trust-registry/issues/219),
[#220](https://github.com/midnightntwrk/midnight-trust-registry/issues/220),
[#232](https://github.com/midnightntwrk/midnight-trust-registry/issues/232),
and [#281](https://github.com/midnightntwrk/midnight-trust-registry/issues/281).
Npm bootstrap and protected publishing are tracked in
[#271](https://github.com/midnightntwrk/midnight-trust-registry/issues/271);
application image publication is tracked in
[#47](https://github.com/midnightntwrk/midnight-trust-registry/issues/47).
