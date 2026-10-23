import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { observeSignedHelmRuntime, validateHelmRuntimeObservation } from "./observe-helm-runtime.mjs";

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
    const securityContext = { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] } };
    const container = { name, image: reference(role), imagePullPolicy: "Never", securityContext };
    const init = { name: "stage-approval", image: reference(role), imagePullPolicy: "Never",
      securityContext };
    const spec = { automountServiceAccountToken: false,
      nodeSelector: { "kubernetes.io/arch": "arm64" },
      containers: [container], ...(name === "api" ? { initContainers: [init] } : {}) };
    workloads.items.push({ kind: "Deployment",
      metadata: { name: `tr-rc-tr-${name}`, namespace: "trust-registry", uid: `dep-${name}`,
        generation: 1, labels },
      spec: { replicas: 1, selector: { matchLabels: labels },
        template: { metadata: { labels }, spec } },
      status: { observedGeneration: 1, readyReplicas: 1, availableReplicas: 1,
        updatedReplicas: 1 } });
    workloads.items.push({ kind: "ReplicaSet",
      metadata: { name: `rs-${name}`, namespace: "trust-registry", uid: `rs-${name}`, labels,
        ownerReferences: [{ kind: "Deployment", uid: `dep-${name}`, controller: true }] },
      spec: { replicas: 1, template: { spec: structuredClone(spec) } }, status: { readyReplicas: 1 } });
    workloads.items.push({ kind: "Pod",
      metadata: { name: `pod-${name}`, namespace: "trust-registry", labels,
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
  pod.status.containerStatuses[0].imageID = `containerd://sha256:${"1".repeat(64)}`;
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
  apiPod.spec.serviceAccountName = "privileged";
  assert.throws(check, /Pod spec differs/u);
  apiPod.spec.serviceAccountName = "default";
  apiPod.spec.dnsPolicy = "ClusterFirst";
  assert.doesNotThrow(check);
});

test("runs read-only kubectl queries only after the signed fleet preflight", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-helm-live-test-"));
  try {
    const mappingPath = join(root, "mapping.json");
    const scopePath = join(root, "scope.json");
    await writeFile(mappingPath, mappingBytes);
    await writeFile(scopePath, scopeBytes);
    const paths = { preflightPaths: { receiptPath: mappingPath }, scopePath,
      kubeconfig: join(root, "kubeconfig"), kubeContext: "isolated-cluster" };
    const { nodes, workloads } = fixture();
    const calls = [];
    const run = async (program, args) => {
      calls.push([program, args]);
      return { stdout: JSON.stringify(args.includes("nodes") ? nodes : workloads) };
    };
    assert.equal((await observeSignedHelmRuntime(paths,
      { checkFleet: async () => fleet, run })).workloads.length, 6);
    assert.equal(calls.length, 2);
    assert.ok(calls.every(([program, args]) => program === "kubectl"
      && args.includes("--context") && args.includes("isolated-cluster")
      && args.includes("--output=json")));
    calls.length = 0;
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => { throw new Error("bad fleet"); }, run,
    }), /bad fleet/u);
    assert.equal(calls.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
