# Trust Registry standalone Helm chart

This versioned chart is an **install template**, not 0.1.0 qualification
evidence. It targets an isolated, arm64, self-hosted local Midnight ledger.
In its default `bootstrap` phase it creates node, indexer, and prover. After
genesis and maintenance approval, `deploymentPhase: runtime` adds the API and
two portals, for six single-replica Deployments and six private ClusterIP
Services in total. It creates no Secret, PVC, Ingress, wallet, ServiceAccount,
governance approval, or public-network resource. See [issue #218](https://github.com/midnightntwrk/midnight-trust-registry/issues/218)
and the [standalone qualification plan](../../docs/guide/standalone-offline-runtime.md).

## Prepare online, then run offline

1. Independently approve the signed source, release manifest, maintenance
   policy, and exact OCI digests. The chart fixes `CFG_PRESET=dev`; observe the
   resulting local genesis on the target cluster and approve its hash during
   first-run setup before signing the API plan. The chart cannot substitute a
   different genesis or self-approve the observed one. Build and verify the v4 install
   bundle. Do not use the dummy digests in `tests/fixture-values.yaml`.
2. During online installation, map each approved archive hash and image ID to
   its private-registry digest after pushing the exact image bytes. Have the
   release reviewer approve that mapping. Preload each resulting
   `registry.example.test/name@sha256:<digest>` reference into the CRI image store
   on **every** eligible arm64 node (for example with `crictl pull`), and
   inspect the local CRI image ID and repo digest on every node against the
   approved mapping. `docker load` on the workstation does not preload a
   Kubernetes node. The chart fixes `imagePullPolicy: Never`; an absent or
   differently named image fails closed instead of pulling. The chart schema
   checks digest syntax, not archive-to-registry provenance. Retain the
   reviewed mapping and node inspection receipts as install evidence.
   Image garbage collection or a replacement node can evict a preloaded
   reference; review cluster retention and credential-verification policy,
   and re-check all exact refs before restart or restore tests.
   Before installation, prepare a six-role mapping receipt in the format below,
   have the release reviewer independently compare the private-registry
   digests with the pushed bytes, and sign the exact JSON file with a detached
   OpenPGP signature. Run the mapping preflight with the approved public
   keyring and fingerprint:

   ```sh
   node scripts/check-helm-image-mapping.mjs \
     <v4-bundle> <admin-image/manifest.json> <applicant-image/manifest.json> \
     <approved-values.yaml> <mapping.json> <mapping.sig> \
     <reviewer-keyring> <REVIEWER_FINGERPRINT>
   ```

   The receipt is a JSON object with `format: "tr-helm-image-mapping-v1"`,
   the bundle's `sourceRevision` and `inventorySha256`, the SHA-256 of the
   exact approved values file as `valuesSha256`, and an `images` array
   containing exactly `node`, `indexer`, `proofServer`, `api`, `admin`, and
   `applicant`. Each image entry has `role`, the chart's exact `reference`,
   the approved `archiveSha256`, its local `imageId`, and the archive's
   `configId`. The verifier hashes
   the v4 bundle and both portal archives, checks those identities against
   the one values file supplied to this command, and verifies the reviewer's
   signature over the mapping. The registry digest is linked to the archive
   **only by that independent human approval**, not cryptographically by this
   tool. Use fully qualified image references with an explicit registry host;
   short Docker Hub names are rejected before install because CRI may report
   their normalized names differently. Retain the preflight output's `mappingSha256` and require every
   node receipt to name that same hash; a signature alone does not recheck
   the install archives on the node. Install with that exact values file and no extra `-f` or `--set`
   overrides; the tool cannot police a later Helm invocation. It does
   **not** prove registry provenance, CRI preload, live image execution, or
   offline behavior. Keep the raw per-node `crictl inspecti` output, node
   identity, and reviewer-approved archive-to-registry comparison separately
   as real-cluster evidence. Never fabricate these observations from tests.
   Once the images are preloaded, run the read-only collector **on each
   eligible Kubernetes node** against that node's explicit CRI image socket:

   ```sh
   node scripts/collect-helm-cri-images.mjs \
     <mapping.json> <mapping.sig> <reviewer-keyring> <REVIEWER_FINGERPRINT> \
     <kubernetes-node-name> unix:///run/containerd/containerd.sock \
     <new-private-node-receipt.json>
   ```

   The collector needs Node.js, `gpgv`, `crictl`, and the two checked-in
   scripts `collect-helm-cri-images.mjs` and
   `verify-helm-mapping-signature.mjs`; it does not pull images or require
   the package workspace. Supply the actual image-service Unix socket for
   that node, not the example path. It requests each signed digest reference
   separately with `crictl inspecti --quiet --output json` and requires an
   exact `repoDigests` match, a CRI image ID equal to the signed archive's
   `configId`, and nonzero size. A generic image import may not preserve the
   exact digest-named reference; check the CRI lookup by that reference before
   using `imagePullPolicy: Never`.
   It writes a new mode-0600 receipt and refuses to overwrite one. Collect
   the raw receipt through a controlled evidence channel; independently
   confirm that the supplied Kubernetes node name belongs to the machine,
   compare receipts with the complete eligible-node inventory, and sign the
   resulting evidence set. The collector's hostname and clock are not
   independent attestations. A receipt only observes one node's CRI store at
   one instant; it does not prove every node was checked, that a pod ran the
   image, that image garbage collection will not evict it, or that egress was
   denied. The current checker expects a `sha256:` CRI image ID; a runtime
   that reports another ID syntax requires a separately reviewed adapter,
   not a weakened match. The exact Kubernetes, CRI runtime, and `crictl`
   versions remain unqualified until a real cluster run. Repeat after
   restart, replacement-node scheduling, or restore.
3. Provide existing PVCs for node chain history, indexer data, and the
   18-file pinned proof-parameter set. The proof PVC is mounted read-only.
   Verify its contents against the install inventory before deployment; this
   chart does not hash PVC contents. Back up node and indexer volumes together
   with their genesis, contract address, release manifest, and operator
   approval record. Never treat an empty replacement PVC as a restore.
4. Before bootstrap, provide an indexer Secret with keys `password` and
   `secret`. Reserve names for the API approval and reviewer-keyring Secrets
   in values, but create those only after genesis is observed and the plan is
   independently approved. The API approval Secret needs keys `api-plan.json`, `api-plan.sig`,
   `install-inventory.json`, `release-manifest.json`, and `snapshot.json`, plus
   a reviewer-keyring Secret with `pubring.kbx`. The detached signed plan must
   refer to these files under `/run/trust-registry/` and to the exact pinned
   local node/indexer service names. Its `sourceRevision` must match the API
   image's `/app/source-revision` file. Provision Secrets using the operator's
   secret manager; never place wallet seeds, private maintenance keys, or
   credentials in Helm values, a ConfigMap, the image, or logs. A Kubernetes
   Secret object remains in cluster storage; enforce at-rest encryption and
   narrowly scoped RBAC separately. Native Secrets have a size limit, so
   large snapshots need a separately reviewed delivery mechanism.
5. Provide a public local beneficiary key, reviewer fingerprint, and real
   digest-pinned image references in a private values file. Install the
   `bootstrap` phase first, observe its genesis, complete the first-run
   wizard's detached approvals, and provision the API Secrets. Then upgrade
   to `deploymentPhase: runtime`. Use a release name beginning with a lowercase
   letter and at most 47 characters; the signed plan's `allowedHosts` and endpoint URLs must use the
   chart's exact short Service names `<release>-tr-node` and
   `<release>-tr-indexer`, not fully qualified cluster DNS names. Do not use
   `--wait` for a runtime upgrade
   until the signed plan and local ledger are actually ready. Run
   `helm lint charts/trust-registry-standalone -f <approved-values>` and
   `helm template rc charts/trust-registry-standalone -n <namespace> -f <approved-values>`.
   Only after inspecting the output and approvals should an operator install
   it. `pnpm run test:helm-standalone` tests templates with synthetic values.

The current chart does not execute the first-run wizard or approve governance;
the operator must carry its signed receipts across the phase transition.
Before the signed API plan's `notAfter`, obtain renewed independent approval,
replace the approval Secret, and roll the API pod. An expired plan fails closed;
Helm does not renew or revoke it.

The API init container idempotently copies projected Secret symlinks into a
private memory-backed volume as UID 1000 with mode 0600; the reviewer keyring
directory becomes 0700. This is required because the API refuses symlinked
approval files. The API then starts in signed, read-only local-ledger mode
with explicit `--cluster-bind`. It has no unsafe demo mutation flag, no
wildcard CORS, and no public Service. The admin and applicant portals serve
static files only. Browser/API routing and TLS require a separately reviewed
same-origin ingress design; they are **not** provided by this chart.

## Isolation and operations

The default NetworkPolicy denies ingress and egress for chart pods. Narrow
rules permit API-to-node/indexer, indexer-to-node, and selected DNS access.
Actor-labelled pods cannot reach node RPC; only the API, indexer, and
operator-labelled pods can. Operator access to the dev-preset RPC is powerful
and must be restricted by namespace RBAC.
In-namespace bootstrap/actor pods must carry
`trust-registry.midnight.network/role=operator` or `=actor` for service ingress.
Namespace RBAC must prevent untrusted users from assigning those labels.
The DNS selectors are configurable because CNI/CoreDNS labels differ by
cluster. No rule grants public-IP egress. Port-forward, host networking,
node-local agents, and CNI behavior require real-cluster verification.

No workload receives a service-account token. The API and portals run as
non-root with read-only root filesystems. Node, indexer, and prover images
have not yet been qualified with a forced non-root UID; the operator must
review image behavior, pre-provision PVC ownership for the image UIDs, Pod
Security admission, and resource requests/limits on the target cluster. All
workload probes are present, but
their live readiness semantics must be validated before release.

Upgrades and rollbacks must preserve the PVCs and replayable approval
evidence. Never silently rotate genesis, maintenance keys, contract address,
or image digests through `helm upgrade`. Take a consistent backup, test
restore in an isolated namespace, and repeat finalized readback after restart.

## Release gates still open

Template tests do not prove a working cluster. The first local RC still
requires real local-ledger deployment and finalized readback, approved
maintenance transition (1-of-3 is smoke only), exact installed image and
proof-byte readback, offline actor journeys with enforced egress denial,
restart/restore/recovery evidence, target Kubernetes/Helm/CNI compatibility
record, and independent security review. Preprod is out of scope.
