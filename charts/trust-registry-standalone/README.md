# Trust Registry standalone Helm chart

This versioned chart is an **install template**, not 0.1.0 qualification
evidence. It targets an isolated, arm64, self-hosted local Midnight ledger.
It creates six single-replica Deployments, six private ClusterIP Services, and
NetworkPolicies. It creates no Secret, PVC, Ingress, wallet, ServiceAccount,
governance approval, or public-network resource. See [issue #218](https://github.com/midnightntwrk/midnight-trust-registry/issues/218)
and the [standalone qualification plan](../../docs/guide/standalone-offline-runtime.md).

## Prepare online, then run offline

1. Independently approve the signed source, release manifest, genesis,
   maintenance policy, and exact OCI digests. Build and verify the v4 install
   bundle. Do not use the dummy digests in `tests/fixture-values.yaml`.
2. Preload every approved OCI image onto **every** eligible arm64 node. The
   chart fixes `imagePullPolicy: Never`, so an absent image fails closed rather
   than pulling from a public registry. The operator may use an internal
   registry during installation, but runtime nodes still need local image
   bytes before egress is denied.
3. Provide existing PVCs for node chain history, indexer data, and the
   18-file pinned proof-parameter set. The proof PVC is mounted read-only.
   Verify its contents against the install inventory before deployment; this
   chart does not hash PVC contents. Back up node and indexer volumes together
   with their genesis, contract address, release manifest, and operator
   approval record. Never treat an empty replacement PVC as a restore.
4. Provide an indexer Secret with keys `password` and `secret`. Provide an
   API approval Secret with keys `api-plan.json`, `api-plan.sig`,
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
   digest-pinned image references in a private values file. Run
   `helm lint charts/trust-registry-standalone -f <approved-values>` and
   `helm template rc charts/trust-registry-standalone -n <namespace> -f <approved-values>`.
   Only after inspecting the output and approvals should an operator install
   it. `pnpm run test:helm-standalone` tests templates with synthetic values.

The API init container copies projected Secret symlinks into a private
memory-backed volume as UID 1000 with mode 0600; the reviewer keyring
directory becomes 0700. This is required because the API refuses symlinked
approval files. The API then starts in signed, read-only local-ledger mode
with explicit `--cluster-bind`. It has no unsafe demo mutation flag, no
wildcard CORS, and no public Service. The admin and applicant portals serve
static files only. Browser/API routing and TLS require a separately reviewed
same-origin ingress design; they are **not** provided by this chart.

## Isolation and operations

The default NetworkPolicy denies ingress and egress for chart pods. Narrow
rules permit API-to-node/indexer, indexer-to-node, and selected DNS access.
In-namespace bootstrap/actor pods must carry
`trust-registry.midnight.network/role=operator` or `=actor` for service ingress.
Namespace RBAC must prevent untrusted users from assigning those labels.
The DNS selectors are configurable because CNI/CoreDNS labels differ by
cluster. No rule grants public-IP egress. Port-forward, host networking,
node-local agents, and CNI behavior require real-cluster verification.

No workload receives a service-account token. The API and portals run as
non-root with read-only root filesystems. Node, indexer, and prover images
have not yet been qualified with a forced non-root UID; the operator must
review image behavior, volume ownership, Pod Security admission, and resource
requests/limits on the target cluster. All workload probes are present, but
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
