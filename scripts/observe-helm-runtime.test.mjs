import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import yaml from "js-yaml";

import { assertWorkloadPodSpecParity, observeSignedHelmRuntime,
  validateHelmRenderedWorkloadParity, validateHelmRuntimeObservation } from "./observe-helm-runtime.mjs";

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
        generation: 1, labels },
      spec: { replicas: 1, strategy: { type: "Recreate" }, selector: { matchLabels: labels },
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
      dnsPolicy: "ClusterFirst", schedulerName: "default-scheduler",
      restartPolicy: "Always", terminationGracePeriodSeconds: 30,
      enableServiceLinks: true };
    assert.doesNotThrow(() => assertWorkloadPodSpecParity(spec, structuredClone(spec), pod,
      deployment.metadata.name));
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
  assert.throws(() => validateHelmRenderedWorkloadParity(Buffer.from("tampered"),
    actualMappingBytes, actualScopeBytes, workloads), /differs from the signed v2 scope/u);
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
    const renderedBytes = Buffer.from(workloads.items.filter((item) => item.kind === "Deployment")
      .map((item) => `---\n${yaml.dump(item)}`).join(""));
    const renderedManifestPath = join(root, "reviewed-render.yaml");
    await writeFile(renderedManifestPath, renderedBytes);
    const observedScopeBytes = Buffer.from(`${JSON.stringify({ ...scope,
      format: "tr-helm-approved-node-scope-v2", renderedManifestSha256: hash(renderedBytes) })}\n`);
    await writeFile(scopePath, observedScopeBytes);
    const observedFleet = { mappingSha256: hash(mappingBytes), scopeSha256: hash(observedScopeBytes) };
    paths.renderedManifestPath = renderedManifestPath;
    const calls = [];
    const run = async (program, args) => {
      calls.push([program, args]);
      return { stdout: JSON.stringify(args.includes("nodes") ? nodes : workloads) };
    };
    assert.equal((await observeSignedHelmRuntime(paths,
      { checkFleet: async () => observedFleet, run })).workloads.length, 6);
    assert.equal(calls.length, 2);
    assert.ok(calls.every(([program, args]) => program === "kubectl"
      && args.includes("--context") && args.includes("isolated-cluster")
      && args.includes("--output=json")));
    calls.length = 0;
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => { throw new Error("bad fleet"); }, run,
    }), /bad fleet/u);
    assert.equal(calls.length, 0);
    await writeFile(renderedManifestPath, "tampered\n");
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => observedFleet, run,
    }), /exact Helm render/u);
    assert.equal(calls.length, 0);
    await writeFile(renderedManifestPath, renderedBytes);
    const linkedRender = join(root, "linked-render.yaml");
    await symlink(renderedManifestPath, linkedRender);
    paths.renderedManifestPath = linkedRender;
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => observedFleet, run,
    }));
    assert.equal(calls.length, 0);
    paths.renderedManifestPath = renderedManifestPath;
    await writeFile(scopePath, scopeBytes);
    await assert.rejects(observeSignedHelmRuntime(paths, {
      checkFleet: async () => ({ mappingSha256: hash(mappingBytes),
        scopeSha256: hash(scopeBytes) }), run,
    }), /Signed v2 scope/u);
    assert.equal(calls.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
