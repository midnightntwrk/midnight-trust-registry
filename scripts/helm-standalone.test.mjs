import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import yaml from "js-yaml";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const chart = resolve(root, "charts/trust-registry-standalone");
const fixture = resolve(chart, "tests/fixture-values.yaml");
const helm = (args) => {
  const result = spawnSync("helm", args, {
    cwd: root, encoding: "utf8", timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
  return result.stdout;
};
const rendered = (phase = "runtime") => yaml.loadAll(helm(["template", "rc", chart,
  "--namespace", "trust-registry", "--values", fixture, "--set", `deploymentPhase=${phase}`])).filter(Boolean);
const role = (object) => object.metadata?.labels?.["app.kubernetes.io/component"]
  ?? object.spec?.selector?.matchLabels?.["app.kubernetes.io/component"]
  ?? object.spec?.podSelector?.matchLabels?.["app.kubernetes.io/component"];

test("chart lints only with explicit operator inputs", () => {
  helm(["lint", chart, "--values", fixture]);
  assert.throws(() => helm(["template", "rc", chart]), /values don't meet the specifications/u);
  assert.throws(() => helm(["template", "rc", chart, "--values", fixture,
    "--set", "images.api=example.invalid/api:latest"]), /images.api/u);
  assert.throws(() => helm(["template", "rc", chart, "--values", fixture,
    "--set", `images.api=midnightntwrk/api@sha256:${"a".repeat(64)}`]), /images.api/u);
  assert.throws(() => helm(["template", "rc", chart, "--values", fixture,
    "--set", `images.api=example.invalid/api:latest@sha256:${"a".repeat(64)}`]), /images.api/u);
  assert.throws(() => helm(["template", "1rc", chart, "--values", fixture]),
    /release name must start with a letter/u);
  assert.throws(() => helm(["template", `r${"a".repeat(47)}`, chart, "--values", fixture]),
    /release name must be at most 47 characters/u);
  assert.throws(() => helm(["template", "rc", chart, "--values", fixture,
    "--set", "secrets.indexerName="]), /secrets.indexerName/u);
  assert.throws(() => helm(["template", "rc", chart, "--values", fixture,
    "--set", "storage.proofParametersClaim="]), /proofParametersClaim/u);
});

test("renders six private digest-pinned runtime workloads without embedded credentials", () => {
  const objects = rendered();
  const deployments = objects.filter((object) => object.kind === "Deployment");
  const services = objects.filter((object) => object.kind === "Service");
  assert.equal(deployments.length, 6);
  assert.equal(services.length, 6);
  assert.deepEqual(deployments.map(role).sort(),
    ["node", "indexer", "proof-server", "api", "admin", "applicant"].sort());
  assert.ok(services.every((service) => service.spec.type === "ClusterIP"));
  assert.ok(objects.every((object) => !["Ingress", "Secret", "PersistentVolumeClaim",
    "ServiceAccount", "ClusterRole", "ClusterRoleBinding"].includes(object.kind)));
  for (const deployment of deployments) {
    const pod = deployment.spec.template.spec;
    assert.equal(deployment.spec.replicas, 1);
    assert.equal(deployment.spec.strategy.type, "Recreate");
    assert.equal(pod.automountServiceAccountToken, false);
    assert.equal(pod.nodeSelector["kubernetes.io/arch"], "arm64");
    for (const container of [...(pod.initContainers ?? []), ...pod.containers]) {
      assert.match(container.image, /@sha256:[0-9a-f]{64}$/u);
      assert.equal(container.imagePullPolicy, "Never");
      assert.ok(container.startupProbe || pod.initContainers?.includes(container));
    }
  }
  const api = deployments.find((deployment) => role(deployment) === "api");
  const pod = api.spec.template.spec;
  const init = pod.initContainers[0];
  assert.equal(init.name, "stage-approval");
  assert.match(init.args[0], /cp \/input\/approval\/api-plan.json/u);
  assert.match(init.args[0], /rm -f \/run\/trust-registry\/api-plan.json/u);
  assert.match(init.args[0], /chmod 700 \/run\/trust-registry\/reviewer-keyring/u);
  assert.equal(pod.volumes.find((volume) => volume.name === "approval-runtime").emptyDir.medium, "Memory");
  assert.deepEqual(pod.volumes.filter((volume) => volume.secret).map((volume) => volume.secret.secretName).sort(),
    ["api-approval", "reviewer-keyring"].sort());
  assert.deepEqual(pod.volumes.filter((volume) => volume.secret)
    .map((volume) => volume.secret.defaultMode), [288, 288]);
  const main = pod.containers[0];
  assert.ok(main.args.includes("--cluster-bind"));
  assert.ok(main.args.includes("--serve-portals"));
  assert.ok(!main.args.includes("--unsafe-demo-mutations"));
  assert.equal(main.securityContext.readOnlyRootFilesystem, true);
  assert.equal(main.startupProbe.timeoutSeconds, 20);
  assert.equal(main.readinessProbe.timeoutSeconds, 20);
  assert.equal(main.livenessProbe.timeoutSeconds, 5);
  assert.doesNotMatch(main.livenessProbe.exec.command.join(" "), /\/health/u);
  assert.equal(main.volumeMounts.find((mount) => mount.name === "approval-runtime").readOnly, true);
  const proof = deployments.find((deployment) => role(deployment) === "proof-server");
  assert.equal(proof.spec.template.spec.volumes[0].persistentVolumeClaim.readOnly, true);
  assert.equal(proof.spec.template.spec.containers[0].volumeMounts[0].readOnly, true);
});

test("bootstrap waits for target genesis approval before creating the API or portals", () => {
  const objects = rendered("bootstrap");
  const deployments = objects.filter((object) => object.kind === "Deployment");
  const services = objects.filter((object) => object.kind === "Service");
  assert.deepEqual(deployments.map(role).sort(), ["node", "indexer", "proof-server"].sort());
  assert.deepEqual(services.map(role).sort(), ["node", "indexer", "proof-server"].sort());
  assert.ok(!JSON.stringify(objects).includes("api-approval"));
  const policies = objects.filter((object) => object.kind === "NetworkPolicy");
  assert.equal(policies.length, 6);
  assert.deepEqual(policies.filter((policy) => policy.spec.policyTypes.includes("Egress"))
    .map(role).filter(Boolean), ["indexer"]);
  assert.ok(policies.some((policy) => policy.metadata.name === "rc-tr-operator-egress"));
  assert.ok(!policies.some((policy) => policy.metadata.name === "rc-tr-actor-egress"));
});

test("default-denies the dedicated namespace and bounds operator and actor egress", () => {
  const policies = rendered().filter((object) => object.kind === "NetworkPolicy");
  assert.equal(policies.length, 11);
  const deny = policies.find((policy) => policy.metadata.name === "rc-tr-default-deny");
  assert.deepEqual(deny.spec.policyTypes.sort(), ["Egress", "Ingress"]);
  assert.deepEqual(deny.spec.podSelector, {});
  assert.equal(deny.spec.ingress, undefined);
  assert.equal(deny.spec.egress, undefined);
  const egress = policies.filter((policy) => policy.spec.policyTypes.includes("Egress") && policy !== deny);
  assert.deepEqual(egress.map(role).filter(Boolean).sort(), ["api", "indexer"]);
  for (const policy of egress) {
    assert.ok(policy.spec.egress.every((entry) => entry.to.every((target) => !target.ipBlock)));
    assert.ok(policy.spec.egress.some((entry) => entry.to.some((target) => target.namespaceSelector
      && target.podSelector)));
  }
  const ingress = policies.filter((policy) => policy.spec.policyTypes.includes("Ingress") && policy !== deny);
  assert.equal(ingress.length, 6);
  assert.ok(ingress.every((policy) => policy.spec.ingress.every((entry) =>
    entry.from.every((source) => source.podSelector && !source.ipBlock))));
  const nodeIngress = ingress.find((policy) => role(policy) === "node");
  assert.ok(nodeIngress);
  assert.ok(nodeIngress.spec.ingress[0].from.every((source) =>
    source.podSelector.matchLabels["trust-registry.midnight.network/role"] !== "actor"));
  for (const [actorRole, expected] of [
    ["operator", ["node", "indexer", "proof-server", "api", "admin", "applicant"]],
    ["actor", ["indexer", "proof-server", "api", "admin", "applicant"]],
  ]) {
    const policy = policies.find((item) => item.metadata.name === `rc-tr-${actorRole}-egress`);
    assert.equal(policy.spec.podSelector.matchLabels["trust-registry.midnight.network/role"], actorRole);
    assert.deepEqual(policy.spec.policyTypes, ["Egress"]);
    assert.deepEqual(policy.spec.egress.filter((entry) => entry.to[0].podSelector
      && !entry.to[0].namespaceSelector)
      .map((entry) => entry.to[0].podSelector.matchLabels["app.kubernetes.io/component"]).sort(), expected.sort());
    assert.ok(policy.spec.egress.every((entry) => entry.to.length === 1
      && !entry.to[0].ipBlock && entry.ports.every((port) => port.protocol === "TCP" || port.protocol === "UDP")));
    assert.equal(policy.spec.egress.filter((entry) => entry.to[0].namespaceSelector).length, 1);
  }
  const bootstrapOperator = rendered("bootstrap").find((object) => object.kind === "NetworkPolicy"
    && object.metadata.name === "rc-tr-operator-egress");
  assert.deepEqual(bootstrapOperator.spec.egress.filter((entry) => !entry.to[0].namespaceSelector)
    .map((entry) => entry.to[0].podSelector.matchLabels["app.kubernetes.io/component"]).sort(),
  ["node", "indexer", "proof-server"].sort());
});
