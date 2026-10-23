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
   different genesis or self-approve the observed one. Build and verify the v6 install
   bundle from the exact approved source. Do not use the dummy digests in
   `tests/fixture-values.yaml`.
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
     <v6-bundle> \
     <approved-values.yaml> <mapping.json> <mapping.sig> \
     <reviewer-keyring> <REVIEWER_FINGERPRINT>
   ```

   A legacy v4 bundle needs two additional arguments immediately after
   `<v4-bundle>`: `<admin-image/manifest.json>` and
   `<applicant-image/manifest.json>`. Do not pass separate portal manifests for
   v5 or v6; their portal archives are pinned inside the install bundle.

   The receipt is a JSON object with `format: "tr-helm-image-mapping-v1"`,
   the bundle's `sourceRevision` and `inventorySha256`, the SHA-256 of the
   exact approved values file as `valuesSha256`, and an `images` array
   containing exactly `node`, `indexer`, `proofServer`, `api`, `admin`, and
   `applicant`. Each image entry has `role`, the chart's exact `reference`,
   the approved `archiveSha256`, its local `imageId`, and the archive's
   `configId`. The verifier hashes
   the v6 bundle and its bundled portal archives, checks those identities against
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
   To check the *approved* node set as one evidence package, export the live
   eligible arm64 node inventory from the intended cluster and have an
   independent reviewer approve the complete set. Record the cluster identity
   and inventory evidence in `clusterReference` and `reviewedReference`.
   For live workload observation, render the exact reviewed values, namespace,
   and release name to a retained YAML file. Review it and record its SHA-256
   in a v2 scope before signing; do not change the render afterward:

   ```sh
   helm template tr-rc charts/trust-registry-standalone -n trust-registry \
     -f <approved-values.yaml> > <approved-render.yaml>
   shasum -a 256 <approved-render.yaml>
   ```

   Sign the exact JSON bytes of an approved scope with a detached OpenPGP
   signature. This example describes the schema, not actual cluster evidence:

   ```json
   {
     "format": "tr-helm-approved-node-scope-v2",
     "sourceRevision": "<40-character source SHA>",
     "mappingSha256": "<SHA-256 of exact signed mapping.json bytes>",
     "renderedManifestSha256": "<SHA-256 of exact reviewed Helm YAML bytes>",
     "namespace": "trust-registry",
     "releaseName": "tr-rc",
     "eligibleNodeSelection": "kubernetes.io/arch=arm64",
     "clusterReference": "<reviewed cluster identity and inventory record>",
     "approvedAt": "<reviewer approval timestamp>",
     "reviewedReference": "<independent reviewer approval record>",
     "nodes": [
       {
         "name": "<Kubernetes node name>",
         "collectorHost": "<collector machine hostname>",
         "imageEndpoint": "unix:///run/containerd/containerd.sock"
       }
     ]
   }
   ```

   Place the private node receipts in a dedicated directory named exactly
   `node-<Kubernetes node name>.json`. Put the mapping preflight input paths
   in `preflight-paths.json` with fields `bundleRoot`, `valuesPath`,
   `receiptPath`, `signaturePath`, `keyringPath`, and `signerFingerprint`, all
   pointing to the same approved v6 install materials. For a legacy v4 bundle,
   also provide `adminManifest` and `applicantManifest`; omit both for v5/v6.
   Run:

   ```sh
   node scripts/check-helm-cri-fleet.mjs \
     <preflight-paths.json> <approved-node-scope.json> <scope.sig> \
     <scope-reviewer-keyring> <SCOPE_REVIEWER_FINGERPRINT> <receipts-directory>
   ```

   This re-runs the signed archive-to-values mapping preflight, verifies the
   scope signature, and rejects missing, extra, duplicate, non-regular,
   pre-approval-timestamp, or identity-mismatched node receipts. Each approved node
   needs a distinct collector hostname. It reports hashes for the scope and each
   receipt so the operator can sign and retain the checked evidence set. It
   does **not** discover eligible nodes, authenticate the machine or clock that made a
   receipt, verify the external inventory record, or prove pod execution,
   egress denial, or offline operation. Timestamp checking only establishes
   that the receipt claims a time no earlier than approval; it does not reject
   future timestamps or prove actual collection time. If a new eligible node is added or a
   node is replaced, approve a new scope and recollect its evidence. Keep
   the RC gate open until the real-cluster install and offline actor journeys
   are independently reviewed.
   Relative preflight paths are resolved from the command's working directory,
   not from `preflight-paths.json`. The signed scope's namespace and release
   name must be independently matched to the actual Helm install invocation;
   this checker does not observe the cluster release.
   After installation, use an explicitly selected, reviewed kubeconfig and
   context for a non-mutating Kubernetes workload observation. The observer
   needs narrowly scoped `get` access to both API Secrets and the API Pod,
   plus `create` on `pods/exec` to run a fixed, read-only hash probe in the API
   container. Limit Secret `get` to the two names with RBAC `resourceNames`;
   restrict these grants to the approved release and evidence operator.
   `pods/exec` is not a read-only Kubernetes RBAC verb:

   ```sh
   node scripts/observe-helm-runtime.mjs \
     <preflight-paths.json> <approved-node-scope.json> <scope.sig> \
     <scope-reviewer-keyring> <SCOPE_REVIEWER_FINGERPRINT> \
     <receipts-directory> <absolute-kubeconfig> <kube-context> \
     <approved-render.yaml> <api-plan.json> <api-plan.sig> \
     <api-plan-reviewer-keyring> <API_PLAN_REVIEWER_FINGERPRINT>
   ```

   This first repeats the signed fleet check, verifies the canonical,
   detached-signed v2 API plan, and checks its deployment identity fields.
   Its source revision, install-inventory digest,
   release-manifest digest, and validity window must match the exact verified
   bundle and signed Helm image mapping before any Kubernetes observation.
   The chart's external API approval and reviewer-keyring Secrets must be
   `immutable: true` and not created after the API Pod (at timestamp precision).
   The observer reads both
   Secrets through the selected Kubernetes API, checks their identities and
   creation times, and compares their exact data with the reviewed plan,
   signature, inventory, manifest, snapshot, and public keyring. It then
   hashes the copied files in the running API container and re-reads the Pod
   identity to reject a concurrent rollout. It does not print Secret data.
   The output records the signed plan, signature and keyring digests, both
   Secret identities, runtime file hashes, signer fingerprint, and observed
   API image ID and reference. Current `immutable: true` status does not
   establish that a Secret was immutable when the Pod started; the runtime
   file readback reports byte equality from inside the API container at
   observation time. A compromised container could falsify the probe. Neither
   check continuously binds the process to the plan. The API independently
   verifies the full plan at startup and on reads.
   The observer then reads the arm64 Node list
   and this release's Deployments, ReplicaSets, and Pods from the selected
   Kubernetes API. It fails if the live arm64 node names differ from the
   approved scope, any expected labelled workload is absent or unready, a Pod is not
   owned through the expected ReplicaSet and Deployment, or a running image
   reference, image ID, or pull policy differs from the approved mapping, or
   an ephemeral debug container is present. It also rejects live Deployment
   Pod specs that differ from the exact signed Helm render. A v1 node scope
   remains valid for fleet receipt checks but is rejected by this live observer.
   Capture the output and raw Kubernetes API responses through an
   access-controlled evidence channel; the Secret response contains private
   snapshot and approval data and must not go into ordinary logs. Retain the
   kubeconfig trust anchor, context, cluster
   identity, RBAC grants, time, and Helm revision. Review kubeconfig `exec`
   plugins and the inherited proxy environment before running: `kubectl` may
   execute credential plugins and use a configured proxy. The command does not
   authenticate the reviewer-approved `clusterReference` against the API,
   prove image bytes executed from the CRI store, prove a running process has
   not changed after observation, verify PVC contents,
   inspect unrelated or unlabelled workloads, measure runtime egress, or
   exercise the local ledger or actor journeys. A later rollout, image-store
   replacement, or plan rotation requires a fresh observation. It compares security-relevant
   Pod specs across each Deployment, owned ReplicaSet, and running Pod,
   including commands, arguments, environment, mounts, volumes, probes,
   security context, and host networking. It requires disabled service-account
   automount, no host namespaces or hostPath volumes, RuntimeDefault seccomp,
   and dropped container capabilities without additions. API and portal root
   filesystems must remain read-only. It compares these Pod-spec fields with
   the signed rendered Deployment templates, selectors, template labels, and
   template annotations. It allows only the matching Kubernetes-generated
   `pod-template-hash` label in ReplicaSet/Pod labels and normalizes documented
   container, service-account, priority, and 300-second eviction defaults.
   ReplicaSet and Pod annotations must match the signed Deployment template;
   admission-added annotations fail closed until explicitly reviewed. Other
   Pod/container fields fail closed on drift, except the running Pod's node
   assignment and separately checked ephemeral containers. A real-cluster
   check is still required to validate API-server defaulting (including
   resource quantities, probe fields,
   and projected volume modes); synthetic tests do not establish it.
   It does **not** compare live Services, NetworkPolicies, PVCs, or unrelated
   workloads with the render. The Kubernetes queries and in-container probe
   are not one atomic snapshot; separate authenticated evidence capture is
   still needed for release review.
   A passing synthetic test is not live qualification evidence.
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
replace the approval Secret, and roll the API pod. The plan also pins the exact
finalized governance count and snapshot digest. After any governed mutation,
the API readiness check fails closed until a new snapshot and sequence map are
independently reviewed, a replacement plan is detached-signed, the approval
Secret is replaced, and the API pod is rolled. Merely updating a projected
Secret does not rerun the init container that copies approved bytes into the
private volume. An expired or stale plan fails closed; Helm does not renew or
revoke it. This manual rotation has not been qualified in a live local actor
journey.

The API init container idempotently copies projected Secret symlinks into a
private memory-backed volume as UID 1000 with mode 0600; the reviewer keyring
directory becomes 0700. This is required because the API refuses symlinked
approval files. The API then starts in signed, read-only local-ledger mode
with explicit `--cluster-bind` and `--serve-portals`. The API image must
contain both portal asset sets under `/app/portals`; it refuses to start if
either entry point is missing. For private applicant journeys, `/admin/`,
`/applicant/`, and `/v1/` must all reach this API Service through one reviewed
HTTPS origin. Do not route either portal path to the separate static portal
Services: those remain internal-only packaging surfaces and cannot host the
same-origin private evidence API. The API has no unsafe demo mutation flag,
wildcard CORS, or public Service. The chart supplies neither Ingress nor TLS;
review and test that routing, browser policy, and egress controls on the
actual cluster.

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
The API ingress rule admits only same-namespace pods labelled as an actor or
operator. A controller in another namespace cannot reach the API without a
separately reviewed narrow policy; do not broaden this rule merely to make
an ingress smoke test pass. The same-origin browser route also needs a
reviewed TLS termination point and a real egress-denied actor test.

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
The API Deployment uses `Recreate` to avoid mixed approved source revisions;
upgrades therefore incur a planned outage. Before an upgrade, verify the new
API image supports `--serve-portals`, and update its exact image pin and signed
plan together in a maintenance window. A Helm rollback does not automatically
restore the previous plan or its validity window.

## Release gates still open

Template tests do not prove a working cluster. The first local RC still
requires real local-ledger deployment and finalized readback, approved
maintenance transition (1-of-3 is smoke only), exact installed image and
proof-byte readback, offline actor journeys with enforced egress denial,
restart/restore/recovery evidence, target Kubernetes/Helm/CNI compatibility
record, and independent security review. Preprod is out of scope.
