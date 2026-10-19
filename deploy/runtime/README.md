# Static runtime images

`build-static-runtime-image.mjs` builds immutable, non-root Node images for the
admin console and applicant portal. Installation may be online; runtime image
startup does not install packages or fetch assets. The operator supplies an
approved digest-pinned Node 24 base image, a fresh absolute output directory,
the expected signed source revision, and its approved OpenPGP signer fingerprint:

```sh
node scripts/build-static-runtime-image.mjs admin 'docker.io/library/node@sha256:<approved-index-digest>' linux/arm64 /private/output/admin '<approved-40-hex-source-sha>' '<approved-40-hex-signer-fingerprint>'
node scripts/build-static-runtime-image.mjs applicant 'docker.io/library/node@sha256:<approved-index-digest>' linux/arm64 /private/output/applicant '<approved-40-hex-source-sha>' '<approved-40-hex-signer-fingerprint>'
```

The builder requires a clean GPG/DCO-signed source head and checks the signing
key's fingerprint (not the primary key's fingerprint when a signing subkey is
used). It exports that exact commit to a temporary directory, installs frozen
dependencies without lifecycle scripts, and runs the light build without
reading or writing Turbo caches. This leaves the checkout's generated keys
untouched. It builds only the chosen portal, rejects nonregular static assets,
and saves an image archive plus a manifest containing the exact source revision,
base digest, platform, image ID, archive SHA-256, and individual public asset
hashes. The manifest attests the inputs and resulting bytes; it does not claim
byte-for-byte build reproducibility. TypeScript declarations and source maps are
excluded from the served image. Preload the archive into
the isolated cluster's private registry or nodes before denying egress. Pin
the resulting distributed image by its registry digest, not a local tag or
image ID. The local archive hash is not a registry digest or proof of runtime
isolation. Test the exact platform and image bytes before release.

The current portals default to a loopback API URL in the browser and let the
operator select another local API URL; ingress/TLS and browser-origin policy
remain deployment responsibilities. There is no Trust Registry API OCI build
in this slice. In particular, the API's existing CLI is file-backed, so these
portal images and a Helm template cannot satisfy #218 or #219 alone. Actual
offline actor journeys, API and wallet continuity, cluster network-policy
enforcement, restore, and independent security review remain release gates.
