import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { inspect } from "node:util";
import yaml from "js-yaml";

import { assertWorkloadPodSpecParity, observeSignedHelmRuntime,
  validateApiApprovalSecret, validateApiKeyringSecret, validateApiRuntimeHashes,
  validateHelmApiPlanBinding, validateHelmRenderedWorkloadParity,
  validateHelmRuntimeObservation } from "./observe-helm-runtime.mjs";

const roles = ["node", "indexer", "proofServer", "api", "admin", "applicant"];
const component = (role) => role === "proofServer" ? "proof-server" : role;
const reference = (role) => `registry.example.test/tr/${role.toLowerCase()}@sha256:${"a".repeat(64)}`;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const mapping = { format: "tr-helm-image-mapping-v1", sourceRevision: "b".repeat(40),
  inventorySha256: "c".repeat(64), valuesSha256: "d".repeat(64),
  images: roles.map((role, index) => ({ role, reference: reference(role),
    imageId: `sha256:${String(index + 1).repeat(64)}`,
    configId: `sha256:${String(index + 1).repeat(64)}`, archiveSha256: "f".repeat(64) })) };
const mappingBytes = Buffer.from(`${JSON.stringify(mapping)}\n`);
const scope = { format: "tr-helm-approved-node-scope-v1", sourceRevision: mapping.sourceRevision,
  mappingSha256: hash(mappingBytes), namespace: "trust-registry", releaseName: "tr-rc",
  eligibleNodeSelection: "kubernetes.io/arch=arm64", clusterReference: "local-cluster-01",
  approvedAt: "2026-10-20T00:00:00Z", reviewedReference: "review-record-01",
  nodes: [{ name: "worker-1", collectorHost: "worker-1",
    imageEndpoint: "unix:///run/containerd/containerd.sock" }] };
const scopeBytes = Buffer.from(`${JSON.stringify(scope)}\n`);
const fleet = { mappingSha256: hash(mappingBytes), scopeSha256: hash(scopeBytes) };
const releaseManifest = Buffer.from("release-manifest");
const snapshot = Buffer.from("snapshot");
const currentPlan = (inventory) => ({ format: "tr-local-api-runtime-v2",
  sourceRevision: mapping.sourceRevision, installInventorySha256: hash(inventory),
  releaseManifestSha256: hash(releaseManifest), snapshotSha256: hash(snapshot),
  notBefore: new Date(Date.now() - 60_000).toISOString(),
  notAfter: new Date(Date.now() + 60_000).toISOString() });

test("binds a canonical signed API plan to the verified Helm mapping and install", () => {
  const inventory = Buffer.from(JSON.stringify({ format: "tr-standalone-install-v6",
    sourceRevision: mapping.sourceRevision, packageManifest: "release-manifest.json",
    packageManifestSha256: hash(releaseManifest) }));
  const signedMapping = Buffer.from(`${JSON.stringify({ ...mapping,
    inventorySha256: hash(inventory) })}\n`);
  const plan = currentPlan(inventory);
  const bytes = Buffer.from(`${JSON.stringify(plan)}\n`);
  const result = validateHelmApiPlanBinding(bytes, signedMapping, inventory);
  assert.equal(result.planSha256, hash(bytes));
  assert.equal(result.apiImageReference, reference("api"));
  const check = (candidate, candidateMapping = signedMapping, candidateInventory = inventory) =>
    validateHelmApiPlanBinding(Buffer.from(`${JSON.stringify(candidate)}\n`),
      candidateMapping, candidateInventory);
  assert.throws(() => check({ ...plan, sourceRevision: "f".repeat(40) }), /does not bind/u);
  assert.throws(() => check({ ...plan, installInventorySha256: "f".repeat(64) }), /does not bind/u);
  assert.throws(() => check({ ...plan, releaseManifestSha256: "f".repeat(64) }), /does not bind/u);
  assert.throws(() => check({ ...plan, format: "tr-local-api-runtime-v1" }), /does not bind/u);
  assert.throws(() => check({ ...plan, notAfter: new Date(Date.now() - 1).toISOString() }),
    /does not bind/u);
  assert.throws(() => check(plan, signedMapping, Buffer.from("tampered")), /changed after/u);
  assert.throws(() => validateHelmApiPlanBinding(Buffer.from(JSON.stringify(plan)
    .replace('"format":"tr-local-api-runtime-v2"',
      '"format":"tr-local-api-runtime-v1","format":"tr-local-api-runtime-v2"')),
  signedMapping, inventory), /canonical JSON/u);
});

test("rejects changed or replaced API approval Secrets without exposing their data", () => {
  const inventory = Buffer.from(JSON.stringify({ format: "tr-standalone-install-v6",
    sourceRevision: mapping.sourceRevision, packageManifest: "release-manifest.json",
    packageManifestSha256: hash(releaseManifest) }));
  const signedMapping = Buffer.from(`${JSON.stringify({ ...mapping,
    inventorySha256: hash(inventory) })}\n`);
  const planBytes = Buffer.from(`${JSON.stringify(currentPlan(inventory))}\n`);
  const signatureBytes = Buffer.from("signature");
  const binding = validateHelmApiPlanBinding(planBytes, signedMapping, inventory);
  const reviewer = "A".repeat(40);
  const pod = { metadata: { creationTimestamp: "2026-10-24T00:01:00.000Z" },
    spec: { containers: [{ name: "api", args: ["--local-ledger-reviewer", reviewer] }],
      volumes: [{ name: "approval-input", secret: { secretName: "api-approval" } }] } };
  const secret = { kind: "Secret", type: "Opaque", immutable: true,
    metadata: { name: "api-approval", namespace: "trust-registry", uid: "secret-1",
      resourceVersion: "42", creationTimestamp: "2026-10-24T00:00:00.000Z" },
    data: Object.fromEntries([
      ["api-plan.json", planBytes], ["api-plan.sig", signatureBytes],
      ["install-inventory.json", inventory], ["release-manifest.json", releaseManifest],
      ["snapshot.json", snapshot],
    ].map(([name, bytes]) => [name, bytes.toString("base64")])) };
  const check = (candidate = secret, observedPod = pod) => validateApiApprovalSecret(
    candidate, observedPod, binding, planBytes, signatureBytes,
    "api-approval", "trust-registry", reviewer);
  assert.equal(check().planSha256, hash(planBytes));
  assert.throws(() => check({ ...secret, immutable: false }), /immutable reviewed Pod input/u);
  assert.throws(() => check({ ...secret, metadata: { ...secret.metadata,
    creationTimestamp: "2026-10-24T00:02:00.000Z" } }), /immutable reviewed Pod input/u);
  assert.equal(check({ ...secret, metadata: { ...secret.metadata,
    creationTimestamp: pod.metadata.creationTimestamp } }).planSha256, hash(planBytes));
  assert.throws(() => check({ ...secret, data: { ...secret.data,
    "api-plan.json": Buffer.from("different").toString("base64") } }), /differs from/u);
  assert.throws(() => check({ ...secret, data: { ...secret.data,
    "api-plan.sig": Buffer.from("different").toString("base64") } }), /differs from/u);
  for (const key of ["install-inventory.json", "release-manifest.json", "snapshot.json"]) {
    assert.throws(() => check({ ...secret, data: { ...secret.data,
      [key]: Buffer.from("different").toString("base64") } }), /differs from/u);
  }
  assert.throws(() => check(secret, { ...pod, spec: { ...pod.spec,
    containers: [{ name: "api", args: ["--local-ledger-reviewer", "B".repeat(40)] }] } }),
  /reviewer differs/u);
  const keyringBytes = Buffer.from("reviewer keyring");
  const keyringPod = { ...pod, spec: { ...pod.spec,
    volumes: [{ name: "keyring-input", secret: { secretName: "api-keyring" } }] } };
  const keyringSecret = { ...secret, metadata: { ...secret.metadata, name: "api-keyring" },
    data: { "pubring.kbx": keyringBytes.toString("base64") } };
  assert.equal(validateApiKeyringSecret(keyringSecret, keyringPod, keyringBytes,
    "api-keyring", "trust-registry").keyringSha256, hash(keyringBytes));
  assert.throws(() => validateApiKeyringSecret(keyringSecret, keyringPod,
    Buffer.from("different"), "api-keyring", "trust-registry"), /differs/u);
  assert.throws(() => validateApiKeyringSecret({ ...keyringSecret, immutable: false },
    keyringPod, keyringBytes, "api-keyring", "trust-registry"), /immutable/u);
  assert.throws(() => validateApiKeyringSecret({ ...keyringSecret,
    metadata: { ...keyringSecret.metadata, creationTimestamp: "2026-10-24T00:02:00.000Z" } },
  keyringPod, keyringBytes, "api-keyring", "trust-registry"), /immutable/u);
  const digests = Object.fromEntries([
    "api-plan.json", "api-plan.sig", "install-inventory.json", "release-manifest.json",
    "snapshot.json", "pubring.kbx"].map((key) => [key, hash(Buffer.from(key))]));
  assert.deepEqual(validateApiRuntimeHashes(digests, digests), digests);
  assert.throws(() => validateApiRuntimeHashes({ ...digests,
    "pubring.kbx": hash(Buffer.from("different")) }, digests), /Running API approval/u);
  assert.throws(() => validateApiRuntimeHashes(digests,
    { "api-plan.json": digests["api-plan.json"] }), /Running API approval/u);
  assert.throws(() => validateApiRuntimeHashes({ ...digests, extra: "0".repeat(64) },
    digests), /Running API approval/u);
});

function fixture() {
  const nodes = { kind: "NodeList", items: [{ kind: "Node",
    metadata: { name: "worker-1", labels: { "kubernetes.io/arch": "arm64" } },
    status: { conditions: [{ type: "Ready", status: "True" }] } }] };
  const workloads = { kind: "List", items: [] };
  for (const role of roles) {
    const name = component(role);
    const labels = { "app.kubernetes.io/instance": "tr-rc",
      "app.kubernetes.io/part-of": "trust-registry-standalone",
      "app.kubernetes.io/component": name };
    const securityContext = { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] },
      ...(["api", "admin", "applicant"].includes(name) ? { readOnlyRootFilesystem: true } : {}) };
    const container = { name, image: reference(role), imagePullPolicy: "Never", securityContext };
    const init = { name: "stage-approval", image: reference(role), imagePullPolicy: "Never",
      securityContext };
    const spec = { automountServiceAccountToken: false,
      nodeSelector: { "kubernetes.io/arch": "arm64" },
      securityContext: { seccompProfile: { type: "RuntimeDefault" } },
      containers: [container], ...(name === "api" ? { initContainers: [init] } : {}) };
    workloads.items.push({ kind: "Deployment",
      metadata: { name: `tr-rc-tr-${name}`, namespace: "trust-registry", uid: `dep-${name}`,
        generation: 1, labels: structuredClone(labels) },
      spec: { replicas: 1, strategy: { type: "Recreate" },
        selector: { matchLabels: structuredClone(labels) },
        template: { metadata: { labels: structuredClone(labels) }, spec } },
      status: { observedGeneration: 1, readyReplicas: 1, availableReplicas: 1,
        updatedReplicas: 1 } });
    workloads.items.push({ kind: "ReplicaSet",
      metadata: { name: `rs-${name}`, namespace: "trust-registry", uid: `rs-${name}`,
        labels: structuredClone(labels),
        ownerReferences: [{ kind: "Deployment", uid: `dep-${name}`, controller: true }] },
      spec: { replicas: 1, template: { metadata: { labels: structuredClone(labels) },
        spec: structuredClone(spec) } },
      status: { readyReplicas: 1 } });
    workloads.items.push({ kind: "Pod",
      metadata: { name: `pod-${name}`, namespace: "trust-registry",
        labels: structuredClone(labels),
        ownerReferences: [{ kind: "ReplicaSet", uid: `rs-${name}`, controller: true }] },
      spec: { ...structuredClone(spec), nodeName: "worker-1" },
      status: { phase: "Running", conditions: [{ type: "Ready", status: "True" }],
        containerStatuses: [{ name, image: reference(role),
          imageID: `containerd://sha256:${String(roles.indexOf(role) + 1).repeat(64)}`,
          containerID: `containerd://${"f".repeat(64)}`, ready: true }],
        ...(name === "api" ? { initContainerStatuses: [{ name: "stage-approval",
          image: reference(role), imageID: `containerd://sha256:${"4".repeat(64)}`,
          containerID: `containerd://${"e".repeat(64)}`,
          state: { terminated: { exitCode: 0 } } }] } : {}) } });
  }
  return { nodes, workloads };
}

test("ties six ready Helm workloads to the signed node scope and image mapping", () => {
  const { nodes, workloads } = fixture();
  const result = validateHelmRuntimeObservation(mappingBytes, scopeBytes, fleet,
    nodes, workloads, "isolated-cluster");
  assert.equal(result.workloads.length, 6);
  assert.equal(result.workloads[3].role, "api");
  assert.match(result.qualification, /not-established/u);
});

test("rejects missing nodes, stale rollout, unowned pods, and image or policy drift", () => {
  const { nodes, workloads } = fixture();
  const check = () => validateHelmRuntimeObservation(mappingBytes, scopeBytes, fleet,
    nodes, workloads, "isolated-cluster");
  nodes.items.push(structuredClone(nodes.items[0]));
  nodes.items[1].metadata.name = "worker-2";
  assert.throws(check, /Live arm64 nodes/u);
  nodes.items.pop();
  const deployment = workloads.items.find((item) => item.kind === "Deployment");
  deployment.status.observedGeneration = 0;
  assert.throws(check, /Deployment is not current/u);
  deployment.status.observedGeneration = 1;
  const pod = workloads.items.find((item) => item.kind === "Pod");
  pod.metadata.ownerReferences[0].uid = "forged-rs";
  assert.throws(check, /not owned/u);
  pod.metadata.ownerReferences[0].uid = "rs-node";
  const replicaSet = workloads.items.find((item) => item.kind === "ReplicaSet");
  delete replicaSet.metadata.uid;
  assert.throws(check, /not owned/u);
  replicaSet.metadata.uid = "rs-node";
  delete pod.metadata.ownerReferences;
  assert.throws(check, /not owned/u);
  pod.metadata.ownerReferences = [{ kind: "ReplicaSet", uid: "rs-node", controller: true }];
  pod.spec.containers[0].imagePullPolicy = "Always";
  assert.throws(check, /Pod spec differs/u);
  pod.spec.containers[0].imagePullPolicy = "Never";
  pod.status.containerStatuses[0].imageID = `containerd://sha256:${"f".repeat(64)}`;
  assert.throws(check, /not running/u);
  pod.status.containerStatuses[0].imageID = `docker-pullable://${reference("node")}`;
  assert.doesNotThrow(check);
  pod.status.containerStatuses[0].imageID = `containerd://sha256:${"1".repeat(64)}`;
  pod.spec.ephemeralContainers = [{ name: "debug", image: "unapproved:latest" }];
  assert.throws(check, /not running/u);
  delete pod.spec.ephemeralContainers;
  pod.status.ephemeralContainerStatuses = [{ name: "debug" }];
  assert.throws(check, /not running/u);
  delete pod.status.ephemeralContainerStatuses;
  const api = workloads.items.find((item) => item.kind === "Pod"
    && item.metadata.labels["app.kubernetes.io/component"] === "api");
  api.status.initContainerStatuses[0].state.terminated.exitCode = 1;
  assert.throws(check, /approval init/u);
  api.status.initContainerStatuses[0].state.terminated.exitCode = 0;
  api.status.initContainerStatuses[0].imageID = `containerd://sha256:${"f".repeat(64)}`;
  assert.throws(check, /approval init/u);
});

test("rejects command, env, volume, and security drift across the workload chain", () => {
  const { nodes, workloads } = fixture();
  const check = () => validateHelmRuntimeObservation(mappingBytes, scopeBytes, fleet,
    nodes, workloads, "isolated-cluster");
  const apiPod = workloads.items.find((item) => item.kind === "Pod"
    && item.metadata.labels["app.kubernetes.io/component"] === "api");
  const apiSet = workloads.items.find((item) => item.kind === "ReplicaSet"
    && item.metadata.labels["app.kubernetes.io/component"] === "api");
  const apiDeployment = workloads.items.find((item) => item.kind === "Deployment"
    && item.metadata.labels["app.kubernetes.io/component"] === "api");
  apiPod.spec.containers[0].args = ["serve", "--unsafe-demo-mutations"];
  assert.throws(check, /Pod spec differs/u);
  delete apiPod.spec.containers[0].args;
  apiSet.spec.template.spec.containers[0].env = [{ name: "UNSAFE", value: "true" }];
  assert.throws(check, /Pod spec differs/u);
  delete apiSet.spec.template.spec.containers[0].env;
  apiPod.spec.volumes = [{ name: "secret", hostPath: { path: "/host" } }];
  assert.throws(check, /Pod spec differs/u);
  delete apiPod.spec.volumes;
  apiPod.spec.containers[0].securityContext.allowPrivilegeEscalation = true;
  assert.throws(check, /Pod spec differs/u);
  apiPod.spec.containers[0].securityContext.allowPrivilegeEscalation = false;
  apiPod.spec.initContainers[0].command = ["sh", "-c", "exit 0"];
  assert.throws(check, /Pod spec differs/u);
  delete apiPod.spec.initContainers[0].command;
  apiPod.spec.containers[0].volumeMounts = [{ name: "host", mountPath: "/run/trust-registry" }];
  assert.throws(check, /Pod spec differs/u);
  delete apiPod.spec.containers[0].volumeMounts;
  apiPod.spec.containers[0].readinessProbe = { exec: { command: ["true"] } };
  assert.throws(check, /Pod spec differs/u);
  delete apiPod.spec.containers[0].readinessProbe;
  apiPod.spec.resourceClaims = [{ name: "unexpected", source: { resourceClaimName: "extra" } }];
  assert.throws(check, /Pod spec differs/u);
  delete apiPod.spec.resourceClaims;
  apiPod.spec.containers[0].resizePolicy = [{ resourceName: "cpu", restartPolicy: "RestartContainer" }];
  assert.throws(check, /Pod spec differs/u);
  delete apiPod.spec.containers[0].resizePolicy;
  apiPod.metadata.annotations = {
    "container.apparmor.security.beta.kubernetes.io/api": "unconfined",
  };
  assert.throws(check, /Legacy AppArmor annotation/u);
  delete apiPod.metadata.annotations;
  apiPod.metadata.annotations = { "k8s.v1.cni.cncf.io/networks": "unapproved" };
  assert.throws(check, /Pod annotations differ/u);
  delete apiPod.metadata.annotations;
  apiSet.spec.template.metadata.annotations = { "mesh.example.test/traffic": "unapproved" };
  assert.throws(check, /Pod annotations differ/u);
  delete apiSet.spec.template.metadata.annotations;
  apiPod.metadata.labels["network-policy.example.test/allow-egress"] = "true";
  assert.throws(check, /Pod labels differ/u);
  delete apiPod.metadata.labels["network-policy.example.test/allow-egress"];
  apiSet.spec.template.metadata.labels["pod-template-hash"] = "abc123";
  apiPod.metadata.labels["pod-template-hash"] = "abc123";
  assert.doesNotThrow(check);
  apiPod.metadata.labels["pod-template-hash"] = "forged";
  assert.throws(check, /Pod labels differ/u);
  delete apiSet.spec.template.metadata.labels["pod-template-hash"];
  delete apiPod.metadata.labels["pod-template-hash"];
  apiDeployment.spec.template.spec.nodeName = "worker-1";
  apiSet.spec.template.spec.nodeName = "worker-1";
  assert.throws(check, /Pod spec differs/u);
  delete apiDeployment.spec.template.spec.nodeName;
  delete apiSet.spec.template.spec.nodeName;
  apiDeployment.spec.template.spec.hostNetwork = true;
  apiSet.spec.template.spec.hostNetwork = true;
  apiPod.spec.hostNetwork = true;
  assert.throws(check, /violates standalone isolation/u);
  delete apiDeployment.spec.template.spec.hostNetwork;
  delete apiSet.spec.template.spec.hostNetwork;
  delete apiPod.spec.hostNetwork;
  for (const value of [apiDeployment.spec.template.spec, apiSet.spec.template.spec, apiPod.spec]) {
    value.volumes = [{ name: "host", hostPath: { path: "/" } }];
  }
  assert.throws(check, /violates standalone isolation/u);
  for (const value of [apiDeployment.spec.template.spec, apiSet.spec.template.spec, apiPod.spec]) {
    delete value.volumes;
  }
  for (const value of [apiDeployment.spec.template.spec, apiSet.spec.template.spec, apiPod.spec]) {
    value.containers[0].securityContext.capabilities.add = ["SYS_ADMIN"];
  }
  assert.throws(check, /violates standalone isolation/u);
  for (const value of [apiDeployment.spec.template.spec, apiSet.spec.template.spec, apiPod.spec]) {
    delete value.containers[0].securityContext.capabilities.add;
    value.securityContext.seccompProfile.type = "Unconfined";
  }
  assert.throws(check, /violates standalone isolation/u);
  for (const value of [apiDeployment.spec.template.spec, apiSet.spec.template.spec, apiPod.spec]) {
    value.securityContext.seccompProfile.type = "RuntimeDefault";
    value.containers[0].securityContext.appArmorProfile = { type: "Unconfined" };
  }
  assert.throws(check, /violates standalone isolation/u);
  for (const value of [apiDeployment.spec.template.spec, apiSet.spec.template.spec, apiPod.spec]) {
    delete value.containers[0].securityContext.appArmorProfile;
    value.containers[0].securityContext.readOnlyRootFilesystem = false;
  }
  assert.throws(check, /violates standalone isolation/u);
  for (const value of [apiDeployment.spec.template.spec, apiSet.spec.template.spec, apiPod.spec]) {
    value.containers[0].securityContext.readOnlyRootFilesystem = true;
  }
  apiPod.spec.serviceAccountName = "privileged";
  assert.throws(check, /Pod spec differs/u);
  apiPod.spec.serviceAccountName = "default";
  apiPod.spec.dnsPolicy = "ClusterFirst";
  assert.doesNotThrow(check);
});

test("accepts all six actual chart Pod templates with ordinary API-server defaults", () => {
  const chart = join(import.meta.dirname, "..", "charts", "trust-registry-standalone");
  const values = join(chart, "tests", "fixture-values.yaml");
  const result = spawnSync("helm", ["template", "rc", chart, "--namespace", "trust-registry",
    "--values", values], { encoding: "utf8", timeout: 30_000, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  const deployments = yaml.loadAll(result.stdout).filter((item) => item?.kind === "Deployment");
  assert.equal(deployments.length, 6);
  for (const deployment of deployments) {
    const spec = deployment.spec.template.spec;
    const pod = { ...structuredClone(spec), serviceAccountName: "default",
      serviceAccount: "default", priority: 0, preemptionPolicy: "PreemptLowerPriority",
      dnsPolicy: "ClusterFirst", schedulerName: "default-scheduler",
      restartPolicy: "Always", terminationGracePeriodSeconds: 30,
      enableServiceLinks: true, tolerations: [
        { key: "node.kubernetes.io/not-ready", operator: "Exists", effect: "NoExecute",
          tolerationSeconds: 300 },
        { key: "node.kubernetes.io/unreachable", operator: "Exists", effect: "NoExecute",
          tolerationSeconds: 300 },
      ] };
    for (const container of [...pod.containers, ...(pod.initContainers ?? [])]) {
      container.stdinOnce = false;
      container.terminationMessagePath = "/dev/termination-log";
      container.terminationMessagePolicy = "File";
    }
    assert.doesNotThrow(() => assertWorkloadPodSpecParity(spec, structuredClone(spec), pod,
      deployment.metadata.name));
    pod.tolerations[0].tolerationSeconds = 600;
    assert.throws(() => assertWorkloadPodSpecParity(spec, structuredClone(spec), pod,
      deployment.metadata.name), /Pod spec differs/u);
    pod.tolerations[0].tolerationSeconds = 300;
    pod.serviceAccount = "privileged";
    assert.throws(() => assertWorkloadPodSpecParity(spec, structuredClone(spec), pod,
      deployment.metadata.name), /Pod spec differs/u);
    pod.serviceAccount = "default";
    pod.containers[0].terminationMessagePath = "/tmp/other-log";
    assert.throws(() => assertWorkloadPodSpecParity(spec, structuredClone(spec), pod,
      deployment.metadata.name), /Pod spec differs/u);
  }
});

test("binds live Deployment Pod specs to the signed exact Helm render", () => {
  const chart = join(import.meta.dirname, "..", "charts", "trust-registry-standalone");
  const values = join(chart, "tests", "fixture-values.yaml");
  const result = spawnSync("helm", ["template", "tr-rc", chart, "--namespace", "trust-registry",
    "--values", values], { encoding: "utf8", timeout: 30_000, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  const renderedBytes = Buffer.from(result.stdout);
  const deployments = yaml.loadAll(result.stdout).filter((item) => item?.kind === "Deployment");
  const actualMapping = structuredClone(mapping);
  for (const image of actualMapping.images) {
    const dep = deployments.find((item) =>
      item.metadata.labels["app.kubernetes.io/component"] === component(image.role));
    image.reference = dep.spec.template.spec.containers[0].image;
  }
  const actualMappingBytes = Buffer.from(`${JSON.stringify(actualMapping)}\n`);
  const actualScope = { ...scope, format: "tr-helm-approved-node-scope-v2",
    mappingSha256: hash(actualMappingBytes), renderedManifestSha256: hash(renderedBytes) };
  const actualScopeBytes = Buffer.from(`${JSON.stringify(actualScope)}\n`);
  const workloads = { kind: "List", items: structuredClone(deployments) };
  for (const deployment of workloads.items) {
    deployment.metadata.namespace = "trust-registry";
    deployment.spec.template.spec.serviceAccountName = "default";
    deployment.spec.template.spec.dnsPolicy = "ClusterFirst";
    deployment.spec.template.spec.restartPolicy = "Always";
    for (const container of [...deployment.spec.template.spec.containers,
      ...(deployment.spec.template.spec.initContainers ?? [])]) {
      container.terminationMessagePath = "/dev/termination-log";
      container.terminationMessagePolicy = "File";
    }
  }
  const apiWorkload = workloads.items.find((item) => item.metadata.name === "tr-rc-tr-api");
  for (const volume of apiWorkload.spec.template.spec.volumes.filter((item) => item.secret)) {
    volume.secret.defaultMode = 288;
  }
  const check = () => validateHelmRenderedWorkloadParity(renderedBytes, actualMappingBytes,
    actualScopeBytes, workloads);
  assert.equal(check(), hash(renderedBytes));
  const api = workloads.items.find((item) => item.metadata.name === "tr-rc-tr-api");
  api.spec.template.spec.initContainers[0].args = ["true"];
  assert.throws(check, /differs from the signed Helm render/u);
  api.spec.template.spec.initContainers[0].args =
    deployments.find((item) => item.metadata.name === "tr-rc-tr-api").spec.template.spec.initContainers[0].args;
  api.spec.template.metadata.annotations = { "security.example.test/override": "unapproved" };
  assert.throws(check, /differs from the signed Helm render/u);
  delete api.spec.template.metadata.annotations;
  api.spec.template.metadata.labels["network-policy.example.test/allow-egress"] = "true";
  assert.throws(check, /differs from the signed Helm render/u);
  delete api.spec.template.metadata.labels["network-policy.example.test/allow-egress"];
  api.spec.selector.matchLabels["network-policy.example.test/allow-egress"] = "true";
  assert.throws(check, /differs from the signed Helm render/u);
  delete api.spec.selector.matchLabels["network-policy.example.test/allow-egress"];
  api.spec.template.spec.nodeName = "worker-1";
  assert.throws(check, /differs from the signed Helm render/u);
  delete api.spec.template.spec.nodeName;
  assert.throws(() => validateHelmRenderedWorkloadParity(Buffer.from("tampered"),
    actualMappingBytes, actualScopeBytes, workloads), /differs from the signed v2 scope/u);
});

test("observes signed fleet, immutable Secrets, and running API file hashes", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-helm-live-test-"));
  try {
    const mappingPath = join(root, "mapping.json");
    const scopePath = join(root, "scope.json");
    const inventory = Buffer.from(JSON.stringify({ format: "tr-standalone-install-v6",
      sourceRevision: mapping.sourceRevision, packageManifest: "release-manifest.json",
      packageManifestSha256: hash(releaseManifest) }));
    const signedMappingBytes = Buffer.from(`${JSON.stringify({ ...mapping,
      inventorySha256: hash(inventory) })}\n`);
    await writeFile(join(root, "install-inventory.json"), inventory);
    const apiPlanPath = join(root, "api-plan.json");
    const signatureBytes = Buffer.from("signature");
    const keyringBytes = Buffer.from("reviewer keyring");
    await writeFile(apiPlanPath, `${JSON.stringify(currentPlan(inventory))}\n`);
    await writeFile(join(root, "api-plan.sig"), signatureBytes);
    await writeFile(join(root, "pubring.kbx"), keyringBytes);
    await writeFile(mappingPath, signedMappingBytes);
    await writeFile(scopePath, scopeBytes);
    const paths = { preflightPaths: { receiptPath: mappingPath, bundleRoot: root }, scopePath,
      kubeconfig: join(root, "kubeconfig"), kubeContext: "isolated-cluster", apiPlanPath,
      apiPlanSignaturePath: join(root, "api-plan.sig"), apiPlanKeyringPath: join(root, "pubring.kbx"),
      apiPlanSignerFingerprint: "A".repeat(40) };
    const { nodes, workloads } = fixture();
    for (const workload of workloads.items.filter((item) =>
      item.metadata?.labels?.["app.kubernetes.io/component"] === "api")) {
      const spec = workload.kind === "Deployment" ? workload.spec.template.spec
        : workload.kind === "ReplicaSet" ? workload.spec.template.spec : workload.spec;
      spec.containers[0].args = ["--local-ledger-reviewer", paths.apiPlanSignerFingerprint];
      spec.volumes = [{ name: "approval-input", secret: { secretName: "api-approval" } },
        { name: "keyring-input", secret: { secretName: "api-keyring" } }];
      if (workload.kind === "Pod") {
        workload.metadata.creationTimestamp = "2026-10-24T00:01:00.000Z";
        workload.metadata.uid = "pod-api-uid";
        workload.metadata.resourceVersion = "53";
      }
    }
    const secret = { kind: "Secret", type: "Opaque", immutable: true,
      metadata: { name: "api-approval", namespace: "trust-registry", uid: "secret-1",
        resourceVersion: "42", creationTimestamp: "2026-10-24T00:00:00.000Z" },
      data: Object.fromEntries([
        ["api-plan.json", await readFile(apiPlanPath)], ["api-plan.sig", signatureBytes],
        ["install-inventory.json", inventory], ["release-manifest.json", releaseManifest],
        ["snapshot.json", snapshot],
      ].map(([name, bytes]) => [name, bytes.toString("base64")])) };
    const keyringSecret = { ...secret,
      metadata: { ...secret.metadata, name: "api-keyring", uid: "keyring-1" },
      data: { "pubring.kbx": keyringBytes.toString("base64") } };
    const apiPod = workloads.items.find((item) => item.kind === "Pod"
      && item.metadata.name === "pod-api");
    const runtimeHashes = {
      "api-plan.json": hash(await readFile(apiPlanPath)),
      "api-plan.sig": hash(signatureBytes),
      "install-inventory.json": hash(inventory),
      "release-manifest.json": hash(releaseManifest),
      "snapshot.json": hash(snapshot),
      "pubring.kbx": hash(keyringBytes),
    };
    const renderedBytes = Buffer.from(workloads.items.filter((item) => item.kind === "Deployment")
      .map((item) => `---\n${yaml.dump(item)}`).join(""));
    const renderedManifestPath = join(root, "reviewed-render.yaml");
    await writeFile(renderedManifestPath, renderedBytes);
    const observedScopeBytes = Buffer.from(`${JSON.stringify({ ...scope,
      mappingSha256: hash(signedMappingBytes), format: "tr-helm-approved-node-scope-v2",
      renderedManifestSha256: hash(renderedBytes) })}\n`);
    await writeFile(scopePath, observedScopeBytes);
    const observedFleet = { mappingSha256: hash(signedMappingBytes),
      scopeSha256: hash(observedScopeBytes) };
    paths.renderedManifestPath = renderedManifestPath;
    const calls = [];
    const run = async (program, args) => {
      calls.push([program, args]);
      const value = args.includes("nodes") ? nodes
        : args.includes("secret") ? args.includes("api-keyring") ? keyringSecret : secret
          : args.includes("exec") ? runtimeHashes
            : args.includes("pod") ? apiPod : workloads;
      return { stdout: JSON.stringify(value) };
    };
    const dependencies = { checkFleet: async () => observedFleet,
      verifyPlanSignature: () => "approved", run };
    const observed = await observeSignedHelmRuntime(paths, dependencies);
    assert.equal(observed.workloads.length, 6);
    assert.equal(observed.apiPlanBinding.planSha256,
      hash(await readFile(apiPlanPath)));
    assert.equal(observed.apiPlanBinding.apiApprovalSecret.secretUid, "secret-1");
    assert.equal(observed.apiPlanBinding.apiKeyringSecret.secretUid, "keyring-1");
    assert.equal(observed.apiPlanBinding.keyringSha256, hash(keyringBytes));
    assert.deepEqual(observed.apiPlanBinding.runtimeApprovalHashes, runtimeHashes);
    assert.equal(calls.length, 6);
    assert.ok(calls.every(([program, args]) => program === "kubectl"
      && args.includes("--context") && args.includes("isolated-cluster")));
    assert.ok(calls.find(([, args]) => args.includes("exec"))?.[1].includes("node"));
    assert.ok(!JSON.stringify(observed).includes(keyringBytes.toString("base64")));
    calls.length = 0;
    await assert.rejects(observeSignedHelmRuntime(paths, { ...dependencies,
      verifyPlanSignature: async () => { throw new Error("bad async signature"); },
    }), /bad async signature/u);
    assert.equal(calls.length, 0);
    await assert.rejects(observeSignedHelmRuntime(paths, { ...dependencies,
      run: async (program, args) => {
        if (args.includes("secret")) throw Object.assign(new Error("private secret bytes"),
          { stdout: "private secret bytes" });
        return run(program, args);
      },
    }), (error) => error.message === "Unable to read approved API Secret"
      && error.cause === undefined && !inspect(error, { showHidden: true })
        .includes("private secret bytes"));
    calls.length = 0;
    await assert.rejects(observeSignedHelmRuntime(paths, { ...dependencies,
      run: async (program, args) => args.includes("secret") && args.includes("api-keyring")
        ? { stdout: JSON.stringify({ ...keyringSecret,
          data: { "pubring.kbx": Buffer.from("substituted keyring").toString("base64") } }) }
        : run(program, args),
    }), /keyring Secret differs/u);
    calls.length = 0;
    await assert.rejects(observeSignedHelmRuntime(paths, { ...dependencies,
      run: async (program, args) => args.includes("exec")
        ? { stdout: JSON.stringify({ ...runtimeHashes, "pubring.kbx": "0".repeat(64) }) }
        : run(program, args),
    }), /Running API approval files differ/u);
    calls.length = 0;
    await assert.rejects(observeSignedHelmRuntime(paths, { ...dependencies,
      run: async (program, args) => {
        if (args.includes("exec")) throw Object.assign(new Error("private runtime bytes"),
          { stdout: "private runtime bytes" });
        return run(program, args);
      },
    }), (error) => error.message === "Unable to read running API approval-file hashes"
      && error.cause === undefined && !inspect(error, { showHidden: true })
        .includes("private runtime bytes"));
    calls.length = 0;
    await assert.rejects(observeSignedHelmRuntime(paths, { ...dependencies,
      run: async (program, args) => args.includes("get") && args.includes("pod")
        ? { stdout: JSON.stringify({ ...apiPod, status: { ...apiPod.status,
          containerStatuses: [{ ...apiPod.status.containerStatuses[0],
            containerID: "containerd://changed" }] } }) } : run(program, args),
    }), /Pod changed during observation/u);
    calls.length = 0;
    await assert.rejects(observeSignedHelmRuntime(paths, { ...dependencies,
      run: async (program, args) => args.includes("get") && args.includes("pod")
        ? { stdout: JSON.stringify({ ...apiPod, status: { ...apiPod.status,
          initContainerStatuses: [{ ...apiPod.status.initContainerStatuses[0],
            containerID: "containerd://changed" }] } }) } : run(program, args),
    }), /Pod changed during observation/u);
    calls.length = 0;
    const stableWithNewVersion = await observeSignedHelmRuntime(paths, { ...dependencies,
      run: async (program, args) => args.includes("get") && args.includes("pod")
        ? { stdout: JSON.stringify({ ...apiPod, metadata: { ...apiPod.metadata,
          resourceVersion: "54" } }) } : run(program, args),
    });
    assert.equal(stableWithNewVersion.apiPlanBinding.apiApprovalSecret.secretUid, "secret-1");
    calls.length = 0;
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => { throw new Error("bad fleet"); },
      verifyPlanSignature: () => "approved", run,
    }), /bad fleet/u);
    assert.equal(calls.length, 0);
    await writeFile(apiPlanPath, `${JSON.stringify({ ...currentPlan(inventory),
      sourceRevision: "f".repeat(40) })}\n`);
    await assert.rejects(observeSignedHelmRuntime(paths, dependencies), /does not bind/u);
    assert.equal(calls.length, 0);
    await writeFile(apiPlanPath, `${JSON.stringify(currentPlan(inventory))}\n`);
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => observedFleet,
      verifyPlanSignature: () => { throw new Error("bad signature"); }, run,
    }), /bad signature/u);
    assert.equal(calls.length, 0);
    await writeFile(renderedManifestPath, "tampered\n");
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => observedFleet, verifyPlanSignature: () => "approved", run,
    }), /exact Helm render/u);
    assert.equal(calls.length, 0);
    await writeFile(renderedManifestPath, renderedBytes);
    const linkedRender = join(root, "linked-render.yaml");
    await symlink(renderedManifestPath, linkedRender);
    paths.renderedManifestPath = linkedRender;
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => observedFleet, verifyPlanSignature: () => "approved", run,
    }));
    assert.equal(calls.length, 0);
    paths.renderedManifestPath = renderedManifestPath;
    const unsignedV1Scope = Buffer.from(`${JSON.stringify({ ...scope,
      mappingSha256: hash(signedMappingBytes) })}\n`);
    await writeFile(scopePath, unsignedV1Scope);
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => ({ mappingSha256: hash(signedMappingBytes),
        scopeSha256: hash(unsignedV1Scope) }), verifyPlanSignature: () => "approved", run,
    }), /Signed v2 scope/u);
    assert.equal(calls.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
