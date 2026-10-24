import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import yaml from "js-yaml";

test("optional API overlay stays on the internal ledger network and requires signed runtime inputs", async () => {
  const base = yaml.load(await readFile(
    fileURLToPath(new URL("../deploy/standalone/compose.yml", import.meta.url)), "utf8"));
  const overlay = yaml.load(await readFile(
    fileURLToPath(new URL("../deploy/standalone/compose.api.yml", import.meta.url)), "utf8"));
  assert.equal(base.networks.ledger.internal, true);
  assert.deepEqual(Object.keys(overlay.services), ["api"]);
  const api = overlay.services.api;
  assert.deepEqual(Object.keys(api).sort(), ["cap_drop", "command", "depends_on", "expose",
    "healthcheck", "image", "init", "networks", "pids_limit", "profiles", "pull_policy",
    "read_only", "security_opt", "tmpfs", "user", "volumes"].sort());
  assert.deepEqual(api.profiles, ["runtime"]);
  assert.deepEqual(api.networks, ["ledger"]);
  assert.equal(api.image, "${TR_API_IMAGE:?verified locally loaded API image required}");
  assert.equal(api.pull_policy, "never");
  assert.equal(api.read_only, true);
  assert.deepEqual(api.cap_drop, ["ALL"]);
  assert.deepEqual(api.security_opt, ["no-new-privileges:true"]);
  assert.equal(api.user, "${TR_API_UID:?approval file owner UID required}:${TR_API_GID:?approval file owner GID required}");
  assert.equal(api.init, true);
  assert.equal(api.pids_limit, 128);
  assert.deepEqual(api.tmpfs, ["/tmp:rw,nosuid,nodev,noexec,size=32m"]);
  assert.deepEqual(api.expose, [4400]);
  assert.equal(api.ports, undefined);
  assert.ok(base.services.node.healthcheck);
  assert.ok(base.services.indexer.healthcheck);
  assert.deepEqual(api.volumes, [{ type: "bind",
    source: "${TR_API_APPROVAL_DIR:?private approved runtime directory required}",
    target: "/run/trust-registry", read_only: true,
    bind: { create_host_path: false } }]);
  assert.deepEqual(api.command, ["serve", "--local-ledger-plan", "/run/trust-registry/api-plan.json",
    "--local-ledger-signature", "/run/trust-registry/api-plan.sig", "--local-ledger-keyring",
    "/run/trust-registry/reviewer-keyring", "--local-ledger-reviewer",
    "${TR_API_REVIEWER_FINGERPRINT:?approved reviewer fingerprint required}", "--host",
    "0.0.0.0", "--cluster-bind", "--serve-portals"]);
  assert.deepEqual(api.depends_on.node, { condition: "service_healthy" });
  assert.deepEqual(api.depends_on.indexer, { condition: "service_healthy" });
  assert.equal(api.healthcheck.interval, "20s");
  assert.equal(api.healthcheck.timeout, "5s");
});
