#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { checkSignedHelmCriFleet, validateApprovedNodeScope } from "./check-helm-cri-fleet.mjs";
import { validateSignedImageMapping } from "./collect-helm-cri-images.mjs";

const execFileAsync = promisify(execFile);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const COMPONENTS = new Map([
  ["node", "node"], ["indexer", "indexer"], ["proofServer", "proof-server"],
  ["api", "api"], ["admin", "admin"], ["applicant", "applicant"],
]);

function exactNames(actual, expected, description) {
  if (actual.length !== expected.length || new Set(actual).size !== actual.length
    || actual.some((name) => !expected.includes(name))) {
    throw new Error(`${description} do not match the approved Helm scope`);
  }
}

export function validateHelmRuntimeObservation(mappingBytes, scopeBytes, fleet, nodes, workloads,
  kubeContext) {
  const mapping = validateSignedImageMapping(JSON.parse(mappingBytes));
  const scope = validateApprovedNodeScope(JSON.parse(scopeBytes), mappingBytes);
  if (fleet?.scopeSha256 !== sha256(scopeBytes) || fleet.mappingSha256 !== sha256(mappingBytes)
    || typeof kubeContext !== "string" || kubeContext.length === 0) {
    throw new Error("Live observation is not bound to the signed scope and mapping");
  }
  if (nodes?.kind !== "NodeList" || !Array.isArray(nodes.items)
    || workloads?.kind !== "List" || !Array.isArray(workloads.items)) {
    throw new Error("kubectl did not return the expected node and workload lists");
  }
  const approvedNodes = scope.nodes.map((node) => node.name);
  exactNames(nodes.items.map((node) => node?.metadata?.name), approvedNodes, "Live arm64 nodes");
  for (const node of nodes.items) {
    if (node.kind !== "Node" || node.metadata.labels?.["kubernetes.io/arch"] !== "arm64"
      || !node.status?.conditions?.some((condition) => condition.type === "Ready"
        && condition.status === "True")) {
      throw new Error(`Approved node is not ready arm64: ${node.metadata?.name}`);
    }
  }

  const expected = mapping.images.map((image) => ({
    role: image.role, component: COMPONENTS.get(image.role), reference: image.reference,
    deploymentName: `${scope.releaseName}-tr-${COMPONENTS.get(image.role)}`,
  }));
  const deployments = workloads.items.filter((item) => item.kind === "Deployment");
  const replicaSets = workloads.items.filter((item) => item.kind === "ReplicaSet");
  const pods = workloads.items.filter((item) => item.kind === "Pod");
  if (deployments.length + replicaSets.length + pods.length !== workloads.items.length) {
    throw new Error("Unexpected resource in Helm workload list");
  }
  exactNames(deployments.map((item) => item.metadata?.name),
    expected.map((entry) => entry.deploymentName), "Live deployments");
  if (pods.length !== expected.length) throw new Error("Live pod count differs from the six-role chart");
  if (replicaSets.filter((item) => item.spec?.replicas > 0).length !== expected.length) {
    throw new Error("Live active ReplicaSet count differs from the six-role chart");
  }

  const observed = [];
  for (const entry of expected) {
    const approvedImage = mapping.images.find((image) => image.role === entry.role);
    const deployment = deployments.find((item) => item.metadata.name === entry.deploymentName);
    const labels = { "app.kubernetes.io/instance": scope.releaseName,
      "app.kubernetes.io/part-of": "trust-registry-standalone",
      "app.kubernetes.io/component": entry.component };
    const hasLabels = (object) => Object.entries(labels).every(([key, value]) =>
      object?.metadata?.labels?.[key] === value);
    const hasSelector = (object) => Object.entries(labels).every(([key, value]) =>
      object?.spec?.selector?.matchLabels?.[key] === value);
    const template = deployment.spec?.template?.spec;
    if (deployment.metadata.namespace !== scope.namespace || !hasLabels(deployment)
      || typeof deployment.metadata.uid !== "string" || deployment.metadata.uid.length === 0
      || deployment.metadata.generation !== deployment.status?.observedGeneration
      || deployment.spec?.replicas !== 1 || deployment.status?.readyReplicas !== 1
      || deployment.status?.availableReplicas !== 1 || deployment.status?.updatedReplicas !== 1
      || !hasSelector(deployment)
      || Object.entries(labels).some(([key, value]) =>
        deployment.spec?.template?.metadata?.labels?.[key] !== value)
      || template?.nodeSelector?.["kubernetes.io/arch"] !== "arm64"
      || template.containers?.length !== 1 || template.containers[0].name !== entry.component
      || template.containers[0].image !== entry.reference
      || template.containers[0].imagePullPolicy !== "Never") {
      throw new Error(`Deployment is not current, ready, or pinned: ${entry.deploymentName}`);
    }
    const pod = pods.filter((item) => hasLabels(item));
    if (pod.length !== 1) throw new Error(`Expected one live pod for ${entry.component}`);
    const running = pod[0];
    const ownedSets = replicaSets.filter((item) => hasLabels(item)
      && item.metadata.namespace === scope.namespace
      && typeof item.metadata.uid === "string" && item.metadata.uid.length > 0
      && item.metadata.ownerReferences?.some((owner) => owner.kind === "Deployment"
        && owner.uid === deployment.metadata.uid && owner.controller === true));
    const podOwner = running.metadata.ownerReferences?.find((owner) => owner.kind === "ReplicaSet"
      && owner.controller === true);
    const liveSet = podOwner && ownedSets.find((item) => item.metadata.uid === podOwner.uid);
    if (!liveSet || ownedSets.filter((item) => item.spec?.replicas > 0).length !== 1
      || liveSet.spec?.replicas !== 1 || liveSet.status?.readyReplicas !== 1
      || liveSet.spec.template?.spec?.containers?.[0]?.image !== entry.reference
      || liveSet.spec.template.spec.containers[0].imagePullPolicy !== "Never") {
      throw new Error(`Pod is not owned by the approved Deployment: ${entry.component}`);
    }
    const container = running.spec?.containers?.[0];
    const status = running.status?.containerStatuses?.[0];
    const observedImageId = typeof status?.imageID === "string"
      ? status.imageID.replace(/^[a-z][a-z0-9+.-]*:\/\//u, "") : "";
    if (running.metadata.namespace !== scope.namespace
      || typeof running.metadata.name !== "string" || running.metadata.name.length === 0
      || running.metadata.deletionTimestamp || running.status?.phase !== "Running"
      || !approvedNodes.includes(running.spec?.nodeName)
      || (running.spec.ephemeralContainers?.length ?? 0) !== 0
      || (running.status.ephemeralContainerStatuses?.length ?? 0) !== 0
      || running.spec.containers?.length !== 1 || container?.name !== entry.component
      || container.image !== entry.reference || container.imagePullPolicy !== "Never"
      || running.status.containerStatuses?.length !== 1 || status?.name !== entry.component
      || status.image !== entry.reference || status.ready !== true
      || (observedImageId !== entry.reference && observedImageId !== approvedImage.configId)
      || typeof status.containerID !== "string" || status.containerID.length === 0
      || !running.status.conditions?.some((condition) => condition.type === "Ready"
        && condition.status === "True")) {
      throw new Error(`Pod is not running the approved image: ${entry.component}`);
    }
    if (entry.component === "api") {
      if (template.initContainers?.length !== 1
        || template.initContainers[0].name !== "stage-approval"
        || template.initContainers[0].image !== entry.reference
        || template.initContainers[0].imagePullPolicy !== "Never"
        || running.spec.initContainers?.length !== 1
        || running.spec.initContainers[0].name !== "stage-approval"
        || running.spec.initContainers[0].image !== entry.reference
        || running.spec.initContainers[0].imagePullPolicy !== "Never"
        || running.spec.initContainers[0].restartPolicy === "Always"
        || running.status.initContainerStatuses?.length !== 1
        || running.status.initContainerStatuses[0].name !== "stage-approval"
        || running.status.initContainerStatuses[0].image !== entry.reference
        || running.status.initContainerStatuses[0].state?.terminated?.exitCode !== 0) {
        throw new Error("API approval init container did not complete from the pinned image");
      }
    } else if ((template.initContainers?.length ?? 0) !== 0
      || (running.spec.initContainers?.length ?? 0) !== 0) {
      throw new Error(`Unexpected init container for ${entry.component}`);
    }
    observed.push({ role: entry.role, deployment: entry.deploymentName,
      pod: running.metadata.name, node: running.spec.nodeName,
      reference: entry.reference, imageID: status.imageID });
  }
  return { format: "tr-helm-live-workload-observation-v1", observedAt: new Date().toISOString(),
    kubeContext, clusterReference: scope.clusterReference, namespace: scope.namespace,
    releaseName: scope.releaseName, scopeSha256: sha256(scopeBytes),
    mappingSha256: sha256(mappingBytes), nodes: [...approvedNodes].sort(), workloads: observed,
    qualification: "not-established: observed Kubernetes state is not an offline actor or restore test" };
}

export async function observeSignedHelmRuntime(paths, dependencies = {}) {
  const fleet = await (dependencies.checkFleet ?? checkSignedHelmCriFleet)(paths);
  const [mappingBytes, scopeBytes] = await Promise.all([
    readFile(paths.preflightPaths.receiptPath), readFile(paths.scopePath),
  ]);
  const scope = validateApprovedNodeScope(JSON.parse(scopeBytes), mappingBytes);
  if (fleet.scopeSha256 !== sha256(scopeBytes)) throw new Error("Approved scope changed after fleet check");
  if (typeof paths.kubeconfig !== "string" || !paths.kubeconfig.startsWith("/")
    || typeof paths.kubeContext !== "string" || paths.kubeContext.length === 0) {
    throw new Error("Explicit absolute kubeconfig and Kubernetes context are required");
  }
  const command = dependencies.run ?? execFileAsync;
  const base = ["--kubeconfig", paths.kubeconfig, "--context", paths.kubeContext,
    "--request-timeout=20s"];
  const selector = `app.kubernetes.io/instance=${scope.releaseName},app.kubernetes.io/part-of=trust-registry-standalone`;
  const options = { timeout: 30_000, maxBuffer: 8 * 1024 * 1024 };
  const nodes = JSON.parse((await command("kubectl", [...base, "get", "nodes", "--selector",
    scope.eligibleNodeSelection, "--output=json", "--chunk-size=0"], options)).stdout);
  const workloads = JSON.parse((await command("kubectl", [...base, "--namespace", scope.namespace,
    "get", "deployments,replicasets,pods", "--selector", selector,
    "--output=json", "--chunk-size=0"], options)).stdout);
  return validateHelmRuntimeObservation(mappingBytes, scopeBytes, fleet, nodes, workloads,
    paths.kubeContext);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 10) {
    throw new Error("Usage: node scripts/observe-helm-runtime.mjs <preflight-paths.json> <scope.json> <scope.sig> <scope-keyring> <scope-signer-fingerprint> <receipts-dir> <absolute-kubeconfig> <kube-context>");
  }
  const [preflightPathsFile, scopePath, scopeSignaturePath, scopeKeyringPath,
    scopeSignerFingerprint, receiptsDirectory, kubeconfig, kubeContext] = process.argv.slice(2);
  const preflightPaths = JSON.parse(await readFile(preflightPathsFile, "utf8"));
  console.log(JSON.stringify(await observeSignedHelmRuntime({ preflightPaths, scopePath,
    scopeSignaturePath, scopeKeyringPath, scopeSignerFingerprint, receiptsDirectory,
    kubeconfig, kubeContext }), null, 2));
}
