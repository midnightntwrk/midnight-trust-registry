#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual, promisify } from "node:util";
import yaml from "js-yaml";

import { checkSignedHelmCriFleet, validateApprovedNodeScope } from "./check-helm-cri-fleet.mjs";
import { validateSignedImageMapping } from "./collect-helm-cri-images.mjs";
import { verifyMappingSignature } from "./verify-helm-mapping-signature.mjs";

const execFileAsync = promisify(execFile);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const COMPONENTS = new Map([
  ["node", "node"], ["indexer", "indexer"], ["proofServer", "proof-server"],
  ["api", "api"], ["admin", "admin"], ["applicant", "applicant"],
]);
const SHA256 = /^[0-9a-f]{64}$/u;
const APPROVAL_SECRET_KEYS = ["api-plan.json", "api-plan.sig",
  "install-inventory.json", "release-manifest.json", "snapshot.json"];
const RUNTIME_APPROVAL_PATHS = {
  "api-plan.json": "/run/trust-registry/api-plan.json",
  "api-plan.sig": "/run/trust-registry/api-plan.sig",
  "install-inventory.json": "/run/trust-registry/install-inventory.json",
  "release-manifest.json": "/run/trust-registry/release-manifest.json",
  "snapshot.json": "/run/trust-registry/snapshot.json",
  "pubring.kbx": "/run/trust-registry/reviewer-keyring/pubring.kbx",
};
const RUNTIME_HASH_SCRIPT = `
const fs=require('node:fs');
const crypto=require('node:crypto');
const paths=${JSON.stringify(RUNTIME_APPROVAL_PATHS)};
const limits={'api-plan.json':1048576,'api-plan.sig':65536,
  'install-inventory.json':1048576,'release-manifest.json':1048576,
  'snapshot.json':67108864,'pubring.kbx':8388608};
const hashes={};
for(const [name,path] of Object.entries(paths)){
  const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try{
    const stat=fs.fstatSync(fd);
    if(!stat.isFile()||stat.size===0||stat.size>limits[name]) throw new Error('invalid runtime file');
    const bytes=fs.readFileSync(fd);
    if(bytes.length!==stat.size) throw new Error('runtime file changed during read');
    hashes[name]=crypto.createHash('sha256').update(bytes).digest('hex');
  } finally { fs.closeSync(fd); }
}
process.stdout.write(JSON.stringify(hashes));`;

export function validateHelmApiPlanBinding(planBytes, mappingBytes, inventoryBytes,
  now = Date.now()) {
  const text = planBytes.toString("utf8");
  const plan = JSON.parse(text);
  if (!Buffer.from(text, "utf8").equals(planBytes)
    || ![JSON.stringify(plan), `${JSON.stringify(plan)}\n`,
      `${JSON.stringify(plan, null, 2)}\n`].includes(text)) {
    throw new Error("Signed API plan must be canonical JSON without duplicate keys");
  }
  const mapping = validateSignedImageMapping(JSON.parse(mappingBytes));
  if (sha256(inventoryBytes) !== mapping.inventorySha256) {
    throw new Error("Helm inventory changed after signed image preflight");
  }
  const inventory = JSON.parse(inventoryBytes);
  const timestamp = (value) => typeof value === "string" && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === value ? Date.parse(value) : Number.NaN;
  if (plan?.format !== "tr-local-api-runtime-v2"
    || plan.sourceRevision !== mapping.sourceRevision
    || plan.installInventorySha256 !== mapping.inventorySha256
    || !SHA256.test(plan.releaseManifestSha256 ?? "")
    || !SHA256.test(plan.snapshotSha256 ?? "")
    || inventory.sourceRevision !== mapping.sourceRevision
    || !["tr-standalone-install-v4", "tr-standalone-install-v5",
      "tr-standalone-install-v6"].includes(inventory.format)
    || inventory.packageManifest !== "release-manifest.json"
    || inventory.packageManifestSha256 !== plan.releaseManifestSha256
    || !Number.isFinite(timestamp(plan.notBefore))
    || !Number.isFinite(timestamp(plan.notAfter))
    || now < timestamp(plan.notBefore) || now > timestamp(plan.notAfter)
    || timestamp(plan.notAfter) - timestamp(plan.notBefore) > 90 * 24 * 60 * 60 * 1000) {
    throw new Error("Signed API plan does not bind the approved Helm install and current validity window");
  }
  const apiImage = mapping.images.find((image) => image.role === "api");
  return { format: "tr-helm-api-plan-binding-v1", planSha256: sha256(planBytes),
    sourceRevision: mapping.sourceRevision, inventorySha256: mapping.inventorySha256,
    releaseManifestSha256: plan.releaseManifestSha256, snapshotSha256: plan.snapshotSha256,
    apiImageReference: apiImage.reference, apiImageConfigId: apiImage.configId };
}

function assertApiSecretMetadata(secret, pod, expectedName, expectedNamespace, volumeName) {
  const podCreated = Date.parse(pod?.metadata?.creationTimestamp ?? "");
  const secretCreated = Date.parse(secret?.metadata?.creationTimestamp ?? "");
  if (secret?.kind !== "Secret" || secret.type !== "Opaque" || secret.immutable !== true
    || secret.metadata?.name !== expectedName
    || secret.metadata?.namespace !== expectedNamespace
    || typeof secret.metadata?.uid !== "string" || secret.metadata.uid.length === 0
    || typeof secret.metadata?.resourceVersion !== "string"
    || secret.metadata.resourceVersion.length === 0
    || !Number.isFinite(podCreated) || !Number.isFinite(secretCreated)
    || secretCreated > podCreated
    || pod?.spec?.volumes?.find((volume) => volume.name === volumeName)
      ?.secret?.secretName !== expectedName
  ) {
    throw new Error("Live API Secret is not the immutable reviewed Pod input");
  }
  return { secretName: expectedName, secretUid: secret.metadata.uid,
    secretResourceVersion: secret.metadata.resourceVersion };
}

function decodedSecretData(secret, expectedKeys) {
  if (secret?.data === null || typeof secret?.data !== "object"
    || Array.isArray(secret.data)
    || Object.keys(secret.data).sort().join("\0") !== [...expectedKeys].sort().join("\0")) {
    throw new Error("Live API Secret has unexpected data keys");
  }
  return Object.fromEntries(expectedKeys.map((key) => {
    const encoded = secret.data[key];
    if (typeof encoded !== "string" || encoded.length === 0
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)) {
      throw new Error(`Live API Secret has invalid ${key} bytes`);
    }
    const bytes = Buffer.from(encoded, "base64");
    if (bytes.toString("base64") !== encoded) {
      throw new Error(`Live API Secret has noncanonical ${key} bytes`);
    }
    return [key, bytes];
  }));
}

export function validateApiApprovalSecret(secret, pod, binding, planBytes, signatureBytes,
  expectedName, expectedNamespace, signerFingerprint) {
  const metadata = assertApiSecretMetadata(secret, pod, expectedName, expectedNamespace,
    "approval-input");
  const container = pod?.spec?.containers?.find((entry) => entry.name === "api");
  const reviewerFlag = container?.args?.indexOf("--local-ledger-reviewer") ?? -1;
  if (reviewerFlag < 0 || container.args[reviewerFlag + 1] !== signerFingerprint) {
    throw new Error("Live API reviewer differs from the approved signer");
  }
  const data = decodedSecretData(secret, APPROVAL_SECRET_KEYS);
  if (!data["api-plan.json"].equals(planBytes)
    || !data["api-plan.sig"].equals(signatureBytes)
    || sha256(data["install-inventory.json"]) !== binding.inventorySha256
    || sha256(data["release-manifest.json"]) !== binding.releaseManifestSha256
    || sha256(data["snapshot.json"]) !== binding.snapshotSha256) {
    throw new Error("Live API approval Secret differs from the signed plan and verified install");
  }
  return { ...metadata, planSha256: binding.planSha256 };
}

export function validateApiKeyringSecret(secret, pod, keyringBytes, expectedName,
  expectedNamespace) {
  const metadata = assertApiSecretMetadata(secret, pod, expectedName, expectedNamespace,
    "keyring-input");
  const data = decodedSecretData(secret, ["pubring.kbx"]);
  if (!data["pubring.kbx"].equals(keyringBytes)) {
    throw new Error("Live API keyring Secret differs from the approved reviewer keyring");
  }
  return { ...metadata, keyringSha256: sha256(keyringBytes) };
}

export function validateApiRuntimeHashes(hashes, expected) {
  if (hashes === null || typeof hashes !== "object" || Array.isArray(hashes)
    || Object.keys(hashes).sort().join("\0")
      !== Object.keys(RUNTIME_APPROVAL_PATHS).sort().join("\0")
    || Object.keys(expected).sort().join("\0")
      !== Object.keys(RUNTIME_APPROVAL_PATHS).sort().join("\0")
    || Object.entries(expected).some(([name, digest]) =>
      !SHA256.test(digest) || hashes[name] !== digest)) {
    throw new Error("Running API approval files differ from the signed plan and Secrets");
  }
  return hashes;
}

function exactNames(actual, expected, description) {
  if (actual.length !== expected.length || new Set(actual).size !== actual.length
    || actual.some((name) => !expected.includes(name))) {
    throw new Error(`${description} do not match the approved Helm scope`);
  }
}

function probeWithDefaults(probe) {
  if (probe === undefined || probe === null) return null;
  return {
    ...probe,
    initialDelaySeconds: probe.initialDelaySeconds ?? 0,
    timeoutSeconds: probe.timeoutSeconds ?? 1,
    periodSeconds: probe.periodSeconds ?? 10,
    successThreshold: probe.successThreshold ?? 1,
    failureThreshold: probe.failureThreshold ?? 3,
  };
}

function securityRelevantContainer(container) {
  return {
    ...container,
    name: container?.name,
    image: container?.image,
    imagePullPolicy: container?.imagePullPolicy,
    command: container?.command ?? [],
    args: container?.args ?? [],
    env: container?.env ?? [],
    envFrom: container?.envFrom ?? [],
    ports: (container?.ports ?? []).map((port) => ({ ...port, protocol: port.protocol ?? "TCP" })),
    volumeMounts: (container?.volumeMounts ?? []).map((mount) => ({
      ...mount, readOnly: mount.readOnly ?? false,
    })),
    volumeDevices: container?.volumeDevices ?? [],
    securityContext: container?.securityContext ?? {},
    resources: container?.resources ?? {},
    startupProbe: probeWithDefaults(container?.startupProbe),
    readinessProbe: probeWithDefaults(container?.readinessProbe),
    livenessProbe: probeWithDefaults(container?.livenessProbe),
    lifecycle: container?.lifecycle ?? null,
    workingDir: container?.workingDir ?? "",
    stdin: container?.stdin ?? false,
    stdinOnce: container?.stdinOnce ?? false,
    tty: container?.tty ?? false,
    terminationMessagePath: container?.terminationMessagePath ?? "/dev/termination-log",
    terminationMessagePolicy: container?.terminationMessagePolicy ?? "File",
    restartPolicy: container?.restartPolicy ?? null,
  };
}

function securityRelevantPodSpec(spec, runningPod = false) {
  const workloadSpec = { ...spec };
  if (runningPod) {
    delete workloadSpec.nodeName;
    delete workloadSpec.ephemeralContainers;
  }
  return {
    ...workloadSpec,
    containers: (spec?.containers ?? []).map(securityRelevantContainer),
    initContainers: (spec?.initContainers ?? []).map(securityRelevantContainer),
    volumes: (spec?.volumes ?? []).map((volume) => volume.persistentVolumeClaim
      ? { ...volume, persistentVolumeClaim: { ...volume.persistentVolumeClaim,
        readOnly: volume.persistentVolumeClaim.readOnly ?? false } }
      : volume),
    nodeSelector: spec?.nodeSelector ?? {},
    securityContext: spec?.securityContext ?? {},
    automountServiceAccountToken: spec?.automountServiceAccountToken ?? true,
    serviceAccountName: spec?.serviceAccountName ?? "default",
    serviceAccount: spec?.serviceAccount ?? spec?.serviceAccountName ?? "default",
    hostNetwork: spec?.hostNetwork ?? false,
    hostPID: spec?.hostPID ?? false,
    hostIPC: spec?.hostIPC ?? false,
    shareProcessNamespace: spec?.shareProcessNamespace ?? false,
    hostUsers: spec?.hostUsers ?? true,
    imagePullSecrets: spec?.imagePullSecrets ?? [],
    affinity: spec?.affinity ?? null,
    tolerations: spec?.tolerations ?? [],
    topologySpreadConstraints: spec?.topologySpreadConstraints ?? [],
    hostAliases: spec?.hostAliases ?? [],
    dnsConfig: spec?.dnsConfig ?? null,
    dnsPolicy: spec?.dnsPolicy ?? "ClusterFirst",
    runtimeClassName: spec?.runtimeClassName ?? null,
    schedulerName: spec?.schedulerName ?? "default-scheduler",
    priorityClassName: spec?.priorityClassName ?? "",
    priority: spec?.priority ?? 0,
    preemptionPolicy: spec?.preemptionPolicy ?? "PreemptLowerPriority",
    restartPolicy: spec?.restartPolicy ?? "Always",
    terminationGracePeriodSeconds: spec?.terminationGracePeriodSeconds ?? 30,
    enableServiceLinks: spec?.enableServiceLinks ?? true,
  };
}

const DEFAULT_EVICTION_TOLERATIONS = ["node.kubernetes.io/not-ready",
  "node.kubernetes.io/unreachable"];

function withoutAdmittedEvictionTolerations(podTolerations, templateTolerations) {
  return podTolerations.filter((toleration) => !(
    DEFAULT_EVICTION_TOLERATIONS.includes(toleration.key)
    && isDeepStrictEqual(toleration, { key: toleration.key, operator: "Exists",
      effect: "NoExecute", tolerationSeconds: 300 })
    && !templateTolerations.some((approved) => approved.key === toleration.key
      && approved.effect === "NoExecute")));
}

function withoutPodTemplateHash(labels) {
  const result = { ...labels };
  delete result["pod-template-hash"];
  return result;
}

export function assertWorkloadPodSpecParity(deploymentSpec, replicaSetSpec, podSpec, component) {
  const template = securityRelevantPodSpec(deploymentSpec);
  const pod = securityRelevantPodSpec(podSpec, true);
  pod.tolerations = withoutAdmittedEvictionTolerations(pod.tolerations, template.tolerations);
  if (!isDeepStrictEqual(template, securityRelevantPodSpec(replicaSetSpec))
    || !isDeepStrictEqual(template, pod)) {
    throw new Error(`Pod spec differs from the observed Deployment template: ${component}`);
  }
  if (template.automountServiceAccountToken !== false
    || template.serviceAccountName !== "default"
    || template.nodeName !== undefined
    || template.hostNetwork || template.hostPID || template.hostIPC
    || template.shareProcessNamespace === true
    || template.securityContext.seccompProfile?.type !== "RuntimeDefault"
    || template.volumes.some((volume) => volume.hostPath !== undefined)
    || [...template.containers, ...template.initContainers].some((container) =>
      container.securityContext.allowPrivilegeEscalation !== false
      || container.securityContext.privileged === true
      || !container.securityContext.capabilities?.drop?.includes("ALL")
      || (container.securityContext.capabilities?.add?.length ?? 0) !== 0
      || container.securityContext.seccompProfile?.type === "Unconfined"
      || container.securityContext.appArmorProfile?.type === "Unconfined")
    || template.securityContext.appArmorProfile?.type === "Unconfined"
    || (["api", "admin", "applicant"].includes(component)
      && [...template.containers, ...template.initContainers].some((container) =>
        container.securityContext.readOnlyRootFilesystem !== true))) {
    throw new Error(`Pod spec violates standalone isolation requirements: ${component}`);
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
    const templateLabels = deployment.spec.template.metadata?.labels ?? {};
    const setLabels = liveSet.spec.template.metadata?.labels ?? {};
    const podLabels = running.metadata.labels ?? {};
    if (!isDeepStrictEqual(withoutPodTemplateHash(setLabels), templateLabels)
      || !isDeepStrictEqual(withoutPodTemplateHash(podLabels), templateLabels)
      || setLabels["pod-template-hash"] !== podLabels["pod-template-hash"]) {
      throw new Error(`Pod labels differ from the approved Deployment template: ${entry.component}`);
    }
    if ([deployment.spec.template, liveSet.spec.template, running].some((object) =>
      Object.keys(object.metadata?.annotations ?? {}).some((key) =>
        key.startsWith("container.apparmor.security.beta.kubernetes.io/")))) {
      throw new Error(`Legacy AppArmor annotation is not approved: ${entry.component}`);
    }
    const templateAnnotations = deployment.spec.template.metadata?.annotations ?? {};
    if (!isDeepStrictEqual(liveSet.spec.template.metadata?.annotations ?? {}, templateAnnotations)
      || !isDeepStrictEqual(running.metadata.annotations ?? {}, templateAnnotations)) {
      throw new Error(`Pod annotations differ from the approved Deployment template: ${entry.component}`);
    }
    assertWorkloadPodSpecParity(template, liveSet.spec.template.spec, running.spec, entry.component);
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
      const initStatus = running.status.initContainerStatuses?.[0];
      const observedInitImageId = typeof initStatus?.imageID === "string"
        ? initStatus.imageID.replace(/^[a-z][a-z0-9+.-]*:\/\//u, "") : "";
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
        || initStatus.name !== "stage-approval"
        || initStatus.image !== entry.reference
        || (observedInitImageId !== entry.reference
          && observedInitImageId !== approvedImage.configId)
        || typeof initStatus.containerID !== "string" || initStatus.containerID.length === 0
        || initStatus.state?.terminated?.exitCode !== 0) {
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
    qualification: "not-established: workload spec parity is not rendered-chart parity, offline actor, or restore evidence" };
}

export function validateHelmRenderedWorkloadParity(renderedBytes, mappingBytes, scopeBytes, workloads) {
  const mapping = validateSignedImageMapping(JSON.parse(mappingBytes));
  const scope = validateApprovedNodeScope(JSON.parse(scopeBytes), mappingBytes);
  if (scope.format !== "tr-helm-approved-node-scope-v2"
    || sha256(renderedBytes) !== scope.renderedManifestSha256) {
    throw new Error("Rendered Helm manifest differs from the signed v2 scope");
  }
  const documents = yaml.loadAll(renderedBytes.toString("utf8")).filter(Boolean);
  const rendered = documents.filter((item) => item?.kind === "Deployment");
  const live = workloads.items.filter((item) => item.kind === "Deployment");
  const expectedNames = mapping.images.map((image) =>
    `${scope.releaseName}-tr-${COMPONENTS.get(image.role)}`);
  exactNames(rendered.map((item) => item?.metadata?.name), expectedNames,
    "Rendered Helm deployments");
  exactNames(live.map((item) => item?.metadata?.name), expectedNames,
    "Live Helm deployments");
  for (const image of mapping.images) {
    const name = `${scope.releaseName}-tr-${COMPONENTS.get(image.role)}`;
    const expected = rendered.find((item) => item.metadata.name === name);
    const actual = live.find((item) => item.metadata.name === name);
    const renderedSpec = expected?.spec?.template?.spec;
    const liveSpec = actual?.spec?.template?.spec;
    if ((expected.metadata.namespace !== undefined && expected.metadata.namespace !== scope.namespace)
      || actual.metadata.namespace !== scope.namespace
      || expected.spec?.replicas !== 1 || actual.spec?.replicas !== 1
      || expected.spec?.strategy?.type !== "Recreate"
      || actual.spec?.strategy?.type !== "Recreate"
      || !isDeepStrictEqual(expected.spec?.selector, actual.spec?.selector)
      || !isDeepStrictEqual(expected.spec?.template?.metadata?.labels,
        actual.spec?.template?.metadata?.labels)
      || !isDeepStrictEqual(expected.spec?.template?.metadata?.annotations ?? {},
        actual.spec?.template?.metadata?.annotations ?? {})
      || renderedSpec?.containers?.length !== 1
      || renderedSpec.containers[0].image !== image.reference
      || !isDeepStrictEqual(securityRelevantPodSpec(renderedSpec),
        securityRelevantPodSpec(liveSpec))) {
      throw new Error(`Live Deployment differs from the signed Helm render: ${name}`);
    }
  }
  return scope.renderedManifestSha256;
}

const SERVICE_ALLOCATED_FIELDS = new Set(["clusterIP", "clusterIPs", "ipFamilies"]);
const SERVICE_SERVER_DEFAULTS = { ipFamilyPolicy: "SingleStack",
  internalTrafficPolicy: "Cluster", sessionAffinity: "None" };

function serviceSpecWithoutServerDefaults(actual, approved) {
  const result = structuredClone(actual);
  for (const key of SERVICE_ALLOCATED_FIELDS) {
    if (!Object.hasOwn(approved, key)) delete result[key];
  }
  for (const [key, value] of Object.entries(SERVICE_SERVER_DEFAULTS)) {
    if (!Object.hasOwn(approved, key) && Object.hasOwn(result, key)) {
      if (result[key] !== value) throw new Error(`Live Service has a non-default ${key}`);
      delete result[key];
    }
  }
  return result;
}

export function validateHelmRenderedNetworkBoundary(renderedBytes, mappingBytes, scopeBytes,
  resources) {
  const mapping = validateSignedImageMapping(JSON.parse(mappingBytes));
  const scope = validateApprovedNodeScope(JSON.parse(scopeBytes), mappingBytes);
  if (scope.format !== "tr-helm-approved-node-scope-v2"
    || sha256(renderedBytes) !== scope.renderedManifestSha256) {
    throw new Error("Network boundary differs from the signed v2 Helm render");
  }
  if (resources?.kind !== "List" || !Array.isArray(resources.items)
    || resources.items.some((item) => !["Service", "NetworkPolicy"].includes(item.kind))) {
    throw new Error("Kubernetes did not return a complete Service and NetworkPolicy list");
  }
  const documents = yaml.loadAll(renderedBytes.toString("utf8")).filter(Boolean);
  const expectedServices = mapping.images.map((image) =>
    `${scope.releaseName}-tr-${COMPONENTS.get(image.role)}`);
  const expectedPolicies = [`${scope.releaseName}-tr-default-deny`,
    ...mapping.images.map((image) =>
      `${scope.releaseName}-tr-${COMPONENTS.get(image.role)}-ingress`),
    `${scope.releaseName}-tr-indexer-egress`, `${scope.releaseName}-tr-api-egress`,
    `${scope.releaseName}-tr-operator-egress`, `${scope.releaseName}-tr-actor-egress`];
  const renderedServices = documents.filter((item) => item.kind === "Service");
  const renderedPolicies = documents.filter((item) => item.kind === "NetworkPolicy");
  const liveServices = resources.items.filter((item) => item.kind === "Service");
  const livePolicies = resources.items.filter((item) => item.kind === "NetworkPolicy");
  exactNames(renderedServices.map((item) => item.metadata?.name), expectedServices,
    "Rendered Helm Services");
  exactNames(renderedPolicies.map((item) => item.metadata?.name), expectedPolicies,
    "Rendered Helm NetworkPolicies");
  exactNames(liveServices.map((item) => item.metadata?.name), expectedServices,
    "Live Helm Services");
  exactNames(livePolicies.map((item) => item.metadata?.name), expectedPolicies,
    "Live Helm NetworkPolicies");
  const defaultDeny = renderedPolicies.find((item) =>
    item.metadata.name === `${scope.releaseName}-tr-default-deny`);
  if (!isDeepStrictEqual(defaultDeny.spec, {
    podSelector: {},
    policyTypes: ["Ingress", "Egress"],
  })) {
    throw new Error("Signed Helm render has no strict namespace-wide default-deny policy");
  }
  for (const expected of renderedServices) {
    const actual = liveServices.find((item) => item.metadata.name === expected.metadata.name);
    if (expected.spec?.type !== "ClusterIP" || actual.spec?.type !== "ClusterIP"
      || isIP(actual.spec.clusterIP) === 0
      || !Array.isArray(actual.spec.clusterIPs)
      || actual.spec.clusterIPs[0] !== actual.spec.clusterIP
      || actual.spec.clusterIPs.some((address) => isIP(address) === 0)
      || (expected.metadata.namespace !== undefined && expected.metadata.namespace !== scope.namespace)
      || actual.metadata.namespace !== scope.namespace || actual.metadata.deletionTimestamp
      || !isDeepStrictEqual(serviceSpecWithoutServerDefaults(actual.spec, expected.spec),
        expected.spec)) {
      throw new Error(`Live Service differs from the signed Helm render: ${expected.metadata.name}`);
    }
  }
  for (const expected of renderedPolicies) {
    const actual = livePolicies.find((item) => item.metadata.name === expected.metadata.name);
    if ((expected.metadata.namespace !== undefined && expected.metadata.namespace !== scope.namespace)
      || actual.metadata.namespace !== scope.namespace || actual.metadata.deletionTimestamp
      || !isDeepStrictEqual(actual.spec, expected.spec)) {
      throw new Error(`Live NetworkPolicy differs from the signed Helm render: ${expected.metadata.name}`);
    }
  }
  return { services: [...expectedServices].sort(), networkPolicies: [...expectedPolicies].sort() };
}

async function boundedFile(path, maxBytes, description) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new Error(`An absolute ${description} path is required`);
  }
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size === 0 || stat.size > maxBytes) {
      throw new Error(`${description} must be a bounded regular file`);
    }
    const bytes = await file.readFile();
    if (bytes.length !== stat.size) throw new Error(`${description} changed during read`);
    return bytes;
  } finally {
    await file.close();
  }
}

const boundedRenderedManifest = (path) => boundedFile(path, 8 * 1024 * 1024, "Signed Helm render");

export async function observeSignedHelmRuntime(paths, dependencies = {}) {
  const fleet = await (dependencies.checkFleet ?? checkSignedHelmCriFleet)(paths);
  const [mappingBytes, scopeBytes] = await Promise.all([
    readFile(paths.preflightPaths.receiptPath), readFile(paths.scopePath),
  ]);
  const scope = validateApprovedNodeScope(JSON.parse(scopeBytes), mappingBytes);
  if (fleet.scopeSha256 !== sha256(scopeBytes)) throw new Error("Approved scope changed after fleet check");
  const renderedBytes = await boundedRenderedManifest(paths.renderedManifestPath);
  if (scope.format !== "tr-helm-approved-node-scope-v2"
    || scope.renderedManifestSha256 !== sha256(renderedBytes)) {
    throw new Error("Signed v2 scope does not approve the exact Helm render");
  }
  const [planBytes, signatureBytes, keyringBytes, inventoryBytes] = await Promise.all([
    boundedFile(paths.apiPlanPath, 1024 * 1024, "Signed API plan"),
    boundedFile(paths.apiPlanSignaturePath, 64 * 1024, "API plan signature"),
    boundedFile(paths.apiPlanKeyringPath, 8 * 1024 * 1024, "API reviewer keyring"),
    boundedFile(join(paths.preflightPaths.bundleRoot, "install-inventory.json"),
      1024 * 1024, "Helm install inventory"),
  ]);
  const signatureDirectory = await mkdtemp(join(tmpdir(), "tr-helm-api-plan-"));
  try {
    const signatureCopy = join(signatureDirectory, "api-plan.sig");
    const keyringCopy = join(signatureDirectory, "pubring.kbx");
    await writeFile(signatureCopy, signatureBytes, { flag: "wx", mode: 0o600 });
    await writeFile(keyringCopy, keyringBytes, { flag: "wx", mode: 0o600 });
    await (dependencies.verifyPlanSignature ?? verifyMappingSignature)(planBytes,
      signatureCopy, keyringCopy, paths.apiPlanSignerFingerprint);
  } finally {
    await rm(signatureDirectory, { recursive: true, force: true });
  }
  const apiPlanBinding = validateHelmApiPlanBinding(planBytes, mappingBytes, inventoryBytes);
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
  const networkResources = JSON.parse((await command("kubectl", [...base, "--namespace", scope.namespace,
    "get", "services,networkpolicies", "--output=json", "--chunk-size=0"], options)).stdout);
  const observed = validateHelmRuntimeObservation(mappingBytes, scopeBytes, fleet, nodes, workloads,
    paths.kubeContext);
  const renderedManifestSha256 = validateHelmRenderedWorkloadParity(renderedBytes,
    mappingBytes, scopeBytes, workloads);
  const networkBoundary = validateHelmRenderedNetworkBoundary(renderedBytes,
    mappingBytes, scopeBytes, networkResources);
  const apiWorkload = observed.workloads.find((workload) => workload.role === "api");
  const apiPod = workloads.items.find((item) => item.kind === "Pod"
    && item.metadata?.name === apiWorkload.pod);
  const approvalSecretName = apiPod.spec.volumes
    .find((volume) => volume.name === "approval-input")?.secret?.secretName;
  const keyringSecretName = apiPod.spec.volumes
    .find((volume) => volume.name === "keyring-input")?.secret?.secretName;
  if (typeof approvalSecretName !== "string" || approvalSecretName.length === 0
    || typeof keyringSecretName !== "string" || keyringSecretName.length === 0
    || !apiPod.metadata?.uid) {
    throw new Error("Approved API Pod has no stable approval inputs");
  }
  const getSecret = async (name) => {
    try {
      return JSON.parse((await command("kubectl", [...base, "--namespace", scope.namespace,
        "get", "secret", name, "--output=json"], options)).stdout);
    } catch {
      throw new Error("Unable to read approved API Secret");
    }
  };
  const approvalSecret = await getSecret(approvalSecretName);
  const apiApprovalSecret = validateApiApprovalSecret(approvalSecret, apiPod, apiPlanBinding,
    planBytes, signatureBytes, approvalSecretName, scope.namespace,
    paths.apiPlanSignerFingerprint);
  const keyringSecret = await getSecret(keyringSecretName);
  const apiKeyringSecret = validateApiKeyringSecret(keyringSecret, apiPod, keyringBytes,
    keyringSecretName, scope.namespace);
  const expectedRuntimeHashes = { "api-plan.json": sha256(planBytes),
    "api-plan.sig": sha256(signatureBytes),
    "install-inventory.json": apiPlanBinding.inventorySha256,
    "release-manifest.json": apiPlanBinding.releaseManifestSha256,
    "snapshot.json": apiPlanBinding.snapshotSha256,
    "pubring.kbx": sha256(keyringBytes) };
  let runtimeHashes;
  try {
    const result = await command("kubectl", [...base, "--namespace", scope.namespace,
      "exec", apiPod.metadata.name, "-c", "api", "--", "node", "-e", RUNTIME_HASH_SCRIPT],
    options);
    runtimeHashes = JSON.parse(result.stdout);
  } catch {
    throw new Error("Unable to read running API approval-file hashes");
  }
  validateApiRuntimeHashes(runtimeHashes, expectedRuntimeHashes);
  let currentPod;
  try {
    currentPod = JSON.parse((await command("kubectl", [...base, "--namespace", scope.namespace,
      "get", "pod", apiPod.metadata.name, "--output=json"], options)).stdout);
  } catch {
    throw new Error("Unable to re-read approved API Pod");
  }
  const initialApiStatus = apiPod.status.containerStatuses.find((entry) => entry.name === "api");
  const currentApiStatus = currentPod.status?.containerStatuses?.find((entry) => entry.name === "api");
  const initialInitStatus = apiPod.status.initContainerStatuses.find((entry) =>
    entry.name === "stage-approval");
  const currentInitStatus = currentPod.status?.initContainerStatuses?.find((entry) =>
    entry.name === "stage-approval");
  if (currentPod.kind !== "Pod"
    || currentPod.metadata?.uid !== apiPod.metadata.uid
    || currentPod.metadata?.name !== apiPod.metadata.name
    || currentPod.metadata?.namespace !== apiPod.metadata.namespace
    || currentPod.metadata?.deletionTimestamp
    || !isDeepStrictEqual(currentPod.metadata?.ownerReferences, apiPod.metadata.ownerReferences)
    || !isDeepStrictEqual(currentPod.metadata?.labels, apiPod.metadata.labels)
    || !isDeepStrictEqual(currentPod.metadata?.annotations ?? {}, apiPod.metadata.annotations ?? {})
    || !currentPod.spec
    || !isDeepStrictEqual(securityRelevantPodSpec(currentPod.spec, true),
      securityRelevantPodSpec(apiPod.spec, true))
    || currentPod.status?.containerStatuses?.length !== 1
    || !initialApiStatus?.containerID || !currentApiStatus?.containerID
    || !initialApiStatus?.imageID || !currentApiStatus?.imageID
    || !initialInitStatus?.containerID || !currentInitStatus?.containerID
    || currentApiStatus?.containerID !== initialApiStatus.containerID
    || currentApiStatus?.restartCount !== initialApiStatus.restartCount
    || currentApiStatus?.imageID !== initialApiStatus.imageID
    || currentApiStatus?.ready !== true
    || currentInitStatus.containerID !== initialInitStatus.containerID) {
    throw new Error("Approved API Pod changed during observation");
  }
  return { ...observed, format: "tr-helm-live-workload-observation-v2",
    renderedManifestSha256, networkBoundary, apiPlanBinding: { ...apiPlanBinding,
      observedImageID: apiWorkload.imageID, apiApprovalSecret, apiKeyringSecret,
      signerFingerprint: paths.apiPlanSignerFingerprint,
      signatureSha256: expectedRuntimeHashes["api-plan.sig"],
      keyringSha256: expectedRuntimeHashes["pubring.kbx"],
      runtimeApprovalHashes: runtimeHashes },
    qualification: "not-established: signed configuration parity is point-in-time, not measured egress denial, offline actor, or restore evidence" };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 15) {
    throw new Error("Usage: node scripts/observe-helm-runtime.mjs <preflight-paths.json> <scope.json> <scope.sig> <scope-keyring> <scope-signer-fingerprint> <receipts-dir> <absolute-kubeconfig> <kube-context> <approved-render.yaml> <api-plan.json> <api-plan.sig> <api-plan-keyring> <api-plan-signer-fingerprint>");
  }
  const [preflightPathsFile, scopePath, scopeSignaturePath, scopeKeyringPath,
    scopeSignerFingerprint, receiptsDirectory, kubeconfig, kubeContext,
    renderedManifestPath, apiPlanPath, apiPlanSignaturePath, apiPlanKeyringPath,
    apiPlanSignerFingerprint] = process.argv.slice(2);
  const preflightPaths = JSON.parse(await readFile(preflightPathsFile, "utf8"));
  console.log(JSON.stringify(await observeSignedHelmRuntime({ preflightPaths, scopePath,
    scopeSignaturePath, scopeKeyringPath, scopeSignerFingerprint, receiptsDirectory,
    kubeconfig, kubeContext, renderedManifestPath, apiPlanPath, apiPlanSignaturePath,
    apiPlanKeyringPath, apiPlanSignerFingerprint }), null, 2));
}
