# Static runtime images

`build-static-runtime-image.mjs` builds immutable, non-root Node images for the
admin console and applicant portal. Installation may be online; runtime image
startup does not install packages or fetch assets. The operator supplies an
approved digest-pinned Node 24 base image, a fresh absolute output directory
whose parent already exists,
the expected signed source revision, and its approved OpenPGP signer fingerprint:

```sh
node scripts/build-static-runtime-image.mjs admin 'docker.io/library/node@sha256:<approved-index-digest>' linux/arm64 /private/output/admin '<approved-40-hex-source-sha>' '<approved-40-hex-signer-fingerprint>'
node scripts/build-static-runtime-image.mjs applicant 'docker.io/library/node@sha256:<approved-index-digest>' linux/arm64 /private/output/applicant '<approved-40-hex-source-sha>' '<approved-40-hex-signer-fingerprint>'
```

The builder requires a clean GPG/DCO-signed source head and checks the signing
key's fingerprint (not the primary key's fingerprint when a signing subkey is
used). It exports that exact commit to a temporary directory, installs frozen
dependencies without lifecycle scripts, and runs the light build without
reading Turbo caches or using a remote cache. Temporary local cache writes are
discarded with the export. This leaves the checkout's generated keys
untouched. It builds only the chosen portal, rejects nonregular static assets,
and saves an image archive plus a manifest containing the exact source revision,
base digest, platform, image ID, archive SHA-256, and individual public asset
hashes. The manifest attests the inputs and resulting bytes; it does not claim
byte-for-byte build reproducibility. TypeScript declarations and source maps are
excluded from the served image. Preload the archive into
the isolated cluster's private registry or nodes before denying egress. Pin
the resulting distributed image by its registry digest, not a local tag or
image ID. The local archive hash is not a registry digest or proof of runtime
isolation. `docker save` by image ID produces an untagged archive; after
`docker load`, tag the verified image ID in the private registry and pin the
resulting registry digest. Test the exact platform and image bytes before release.

The separate portal images default to a loopback API URL in the browser and
let the operator select another local API URL. For private applicant journeys,
use the API image's opt-in `--serve-portals` mode instead: its builder stages
both portal builds in `/app/portals`, and the API serves `/admin/` and
`/applicant/` from the API origin. The install inventory pins the complete OCI
archive. New API image manifests record the embedded admin and applicant
asset-set hashes; the v5/v6 install verifier checks them against the separately
pinned static portal manifests. Older v1 API manifests remain readable but
provide no cross-image asset-set check. Manifest agreement does not
independently verify API image layer contents. This is packaging and route
evidence, not a verified offline deployment; ingress/TLS, browser-origin policy,
and independent verification of packaged portal bytes remain deployment
responsibilities. The CLI does not yet wire live private-evidence and proposal
submission ports into local-ledger API mode, so the private applicant and governed flows
are not qualified by same-origin routing alone. Read-only proposal-evidence
queries do use the same pinned, snapshot-bound finalized ledger reader as
other local API queries; this does not enable proposal submission. Readback
fails closed after governance state advances beyond the signed snapshot until
the operator approves a refreshed snapshot and runtime plan.
The portal images, API image, and Helm template do not satisfy #218 or #219 by
themselves. Actual local-ledger
readback, offline actor journeys, API and wallet continuity, cluster
network-policy enforcement, restore, and independent security review remain
release gates.
