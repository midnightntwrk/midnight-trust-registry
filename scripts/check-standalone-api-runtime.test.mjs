import assert from "node:assert/strict";
import { test } from "node:test";

import { checkStandaloneApiRuntime } from "./check-standalone-api-runtime.mjs";

const project = "tr-standalone-local-api-test";
const ledger = `${project}_ledger`;
const sourceRevision = "a".repeat(40);
const imageId = (role) => `sha256:${({ api: "a", node: "b", indexer: "c",
  "proof-server": "d" })[role].repeat(64)}`;
const expected = {
  project, sourceRevision, approvalDir: "/private/approved-api",
  inventorySha256: "f".repeat(64),
  uid: "501", gid: "20", reviewerFingerprint: "A".repeat(40),
  composeFiles: ["/bundle/compose.yml", "/bundle/compose.offline.yml", "/bundle/compose.api.yml"],
  apiRuntime: { imageId: imageId("api"), configId: imageId("api") },
  apiImageEnv: ["NODE_ENV=production", "PATH=/usr/local/bin"],
  images: ["node", "indexer", "proof-server"].map((role) => ({ role,
    acceptedIds: [imageId(role)] })),
};
const command = ["serve", "--local-ledger-plan", "/run/trust-registry/api-plan.json",
  "--local-ledger-signature", "/run/trust-registry/api-plan.sig",
  "--local-ledger-keyring", "/run/trust-registry/reviewer-keyring",
  "--local-ledger-reviewer", expected.reviewerFingerprint,
  "--host", "0.0.0.0", "--cluster-bind", "--serve-portals"];
const healthcheck = ["CMD", "node", "-e",
  "fetch('http://127.0.0.1:4400/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"];
const container = (role) => ({
  Id: `${role}-id`, Image: imageId(role),
  RestartCount: 0,
  Config: {
    Image: `tr-standalone/${role}:sha-${sourceRevision}`,
    Labels: {
      "com.docker.compose.project": project,
      "com.docker.compose.service": role,
      "com.docker.compose.project.config_files": expected.composeFiles.join(","),
    },
    ...(role === "api" ? { User: "501:20", Env: [...expected.apiImageEnv],
      Entrypoint: ["node", "/app/bin/trust-registry-api.mjs"], Cmd: command,
      Healthcheck: { Test: healthcheck } } : {}),
  },
  State: { Running: true, Paused: false, StartedAt: "2026-10-24T11:00:00Z",
    Health: { Status: "healthy" } },
  HostConfig: role === "api" ? {
    ReadonlyRootfs: true, Privileged: false, CapDrop: ["ALL"], CapAdd: null,
    SecurityOpt: ["no-new-privileges:true"], PidsLimit: 128, Init: true,
    PortBindings: {}, Tmpfs: { "/tmp": "rw,nosuid,nodev,noexec,size=33554432" },
  } : {},
  NetworkSettings: { Networks: { [ledger]: { NetworkID: "ledger-id" } },
    Ports: role === "api" ? { "4400/tcp": null } : {} },
  Mounts: role === "api" ? [{ Type: "bind", Source: expected.approvalDir,
    Destination: "/run/trust-registry", RW: false }] : [],
});
const containers = ["api", "indexer", "node", "proof-server"].map(container);
const network = { Name: ledger, Id: "ledger-id", Internal: true, Driver: "bridge",
  EnableIPv6: false, Labels: { "com.docker.compose.project": project },
  Containers: Object.fromEntries(containers.map((item) => [item.Id, {}])) };

function drift(mutator) {
  const changedNetwork = structuredClone(network);
  const changedContainers = structuredClone(containers);
  mutator(changedNetwork, changedContainers);
  return () => checkStandaloneApiRuntime(changedNetwork, changedContainers, expected);
}

test("reports a topology observation without a release or finality claim", () => {
  assert.deepEqual(checkStandaloneApiRuntime(network, containers, expected), {
    kind: "standalone-api-runtime-topology-observation", project,
    networkId: "ledger-id", apiContainerId: "api-id",
    apiStartedAt: "2026-10-24T11:00:00Z", apiRestartCount: 0,
    sourceRevision, installInventorySha256: expected.inventorySha256,
    imageIdsMatched: true,
    approvalMountReadOnly: true, internalNetworkOnly: true,
    hostPortPublished: false, finalizedReadback: "not-verified",
    egressDenied: "not-verified", actorJourneys: "not-run",
    releaseQualified: false,
  });
});

test("rejects image, command, identity, and Compose input drift", () => {
  assert.throws(drift((_network, items) => { items[0].Image = imageId("node"); }), /image differs/u);
  assert.throws(drift((_network, items) => { items[0].Config.Image = "tr-standalone/api:latest"; }),
    /image differs/u);
  assert.throws(drift((_network, items) => { items[0].Config.Cmd.push("--unsafe"); }),
    /command or approved identity/u);
  assert.throws(drift((_network, items) => { items[0].Config.User = "0:0"; }),
    /command or approved identity/u);
  assert.throws(drift((_network, items) => {
    items[0].Config.Labels["com.docker.compose.project.config_files"] = "/other/compose.yml";
  }), /command or approved identity/u);
  assert.throws(drift((_network, items) => { items[0].Config.Env.push("NODE_OPTIONS=--require=/app/evil.js"); }),
    /process environment differs/u);
  assert.throws(drift((_network, items) => { items[0].Config.Env.push("NODE_ENV=development"); }),
    /duplicate variables/u);
});

test("rejects writable approval data, privilege drift, and host publishing", () => {
  assert.throws(drift((_network, items) => { items[0].Mounts[0].RW = true; }),
    /approval mount/u);
  assert.throws(drift((_network, items) => { items[0].Mounts[0].Source = "/other"; }),
    /approval mount/u);
  assert.throws(drift((_network, items) => { items[0].HostConfig.ReadonlyRootfs = false; }),
    /privileges/u);
  assert.throws(drift((_network, items) => { items[0].HostConfig.PidMode = "host"; }),
    /privileges/u);
  assert.throws(drift((_network, items) => { items[0].HostConfig.SecurityOpt.push("seccomp=unconfined"); }),
    /privileges/u);
  assert.throws(drift((_network, items) => { items[0].HostConfig.Sysctls = {
    "net.ipv4.ip_forward": "1",
  }; }), /privileges/u);
  assert.throws(drift((_network, items) => { items[0].HostConfig.Tmpfs["/tmp"] =
    "rw,nosuid,nodev,noexec,size=1g"; }), /temporary filesystem/u);
  assert.throws(drift((_network, items) => { items[0].HostConfig.Tmpfs["/app"] = "rw,exec"; }),
    /temporary filesystem/u);
  assert.throws(drift((_network, items) => { items[0].HostConfig.Tmpfs["/tmp"] =
    "rw,nosuid,nodev,noexec,exec,size=33554432"; }), /temporary filesystem/u);
  assert.throws(drift((_network, items) => { items[0].HostConfig.PortBindings = {
    "4400/tcp": [{ HostIp: "0.0.0.0", HostPort: "4400" }],
  }; }), /privileges/u);
  assert.throws(drift((_network, items) => { items[0].NetworkSettings.Ports["4400/tcp"] = [
    { HostIp: "127.0.0.1", HostPort: "4400" },
  ]; }), /privileges/u);
});

test("rejects external or extra network attachments and incomplete services", () => {
  assert.throws(drift((net) => { net.Internal = false; }), /internal ledger/u);
  assert.throws(drift((net) => { net.Containers["outsider-id"] = {}; }), /extra or missing/u);
  assert.throws(drift((_network, items) => { items[0].NetworkSettings.Networks.bridge = {
    NetworkID: "outside",
  }; }), /non-internal network/u);
  assert.throws(drift((_network, items) => { delete items[0].NetworkSettings; }),
    /non-internal network/u);
  assert.throws(drift((_network, items) => { items[0].State.Running = false; }), /unhealthy/u);
  assert.throws(drift((_network, items) => { delete items[0].Config.Healthcheck; }), /health check/u);
  assert.throws(drift((_network, items) => { delete items[0].State.Health; }), /health check/u);
  assert.throws(drift((_network, items) => { delete items[0].State.StartedAt; }), /start and restart/u);
  assert.throws(drift((_network, items) => { items[0].State.StartedAt = "not-a-time"; }),
    /start and restart/u);
  assert.throws(drift((_network, items) => { delete items[0].RestartCount; }), /start and restart/u);
  assert.throws(drift((_network, items) => { items[0].RestartCount = -1; }), /start and restart/u);
  assert.throws(drift((_network, items) => { items[0].Config.Healthcheck.Test = ["CMD", "true"]; }),
    /health check/u);
  assert.throws(drift((_network, items) => {
    items[1].Config.Labels["com.docker.compose.service"] = "api";
  }), /duplicated/u);
});

test("rejects incomplete caller pins", () => {
  assert.throws(() => checkStandaloneApiRuntime(network, containers, {
    ...expected, inventorySha256: "bad",
  }), /inputs are incomplete/u);
  assert.throws(() => checkStandaloneApiRuntime(network, containers, {
    ...expected, reviewerFingerprint: "bad",
  }), /inputs are incomplete/u);
  assert.throws(() => checkStandaloneApiRuntime(network, containers, {
    ...expected, uid: "0",
  }), /inputs are incomplete/u);
  assert.throws(() => checkStandaloneApiRuntime(network, containers, {
    ...expected, gid: "0",
  }), /inputs are incomplete/u);
  assert.throws(() => checkStandaloneApiRuntime(network, containers, {
    ...expected, approvalDir: "/",
  }), /inputs are incomplete/u);
});
