import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { assessStandaloneActorCapability } from "./check-standalone-actor-capability.mjs";

const plan = "a".repeat(64);
const run = promisify(execFile);
const cli = fileURLToPath(new URL("./check-standalone-actor-capability.mjs", import.meta.url));
const health = {
  status: "ok", sourceMode: "local-ledger", localPlanSha256: plan,
  finalizedBlockHash: `0x${"b".repeat(64)}`,
  configuredGovernedProposalRoles: ["issuer"],
};

test("a configured issuer port is only a pre-actor observation", () => {
  const report = assessStandaloneActorCapability(health, plan);
  assert.equal(report.requestedPortsConfigured, true);
  assert.equal(report.actorJourney, "not-run");
  assert.equal(report.independentFinality, "not-verified");
  assert.equal(report.releaseQualified, false);
});

test("read-only CLI, wrong plan, and missing roles fail the capability check", () => {
  assert.equal(assessStandaloneActorCapability({ ...health,
    configuredGovernedProposalRoles: [] }, plan).requestedPortsConfigured, false);
  assert.equal(assessStandaloneActorCapability(health, "c".repeat(64)).planMatchesCandidate, false);
  assert.deepEqual(assessStandaloneActorCapability(health, plan, ["issuer", "verifier"]).missingRoles,
    ["verifier"]);
});

test("unbound, malformed, or duplicate role observations are rejected", () => {
  for (const malformed of [
    null,
    {},
    { ...health, localPlanSha256: null },
    { ...health, finalizedBlockHash: null },
    { ...health, configuredGovernedProposalRoles: null },
    { ...health, configuredGovernedProposalRoles: ["issuer", null] },
    { ...health, configuredGovernedProposalRoles: ["issuer", "unknown"] },
  ]) assert.throws(() => assessStandaloneActorCapability(malformed, plan));
  assert.throws(() => assessStandaloneActorCapability({ ...health, sourceMode: "memory" }, plan));
  assert.throws(() => assessStandaloneActorCapability({ ...health, finalizedBlockHash: `0x${"0".repeat(64)}` }, plan));
  assert.throws(() => assessStandaloneActorCapability({ ...health,
    configuredGovernedProposalRoles: ["issuer", "issuer"] }, plan));
  assert.throws(() => assessStandaloneActorCapability(health, plan, ["issuer", "issuer"]));
});

test("CLI exits 2 for the packaged read-only role set and 0 for a configured port", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-actor-capability-"));
  const path = join(directory, "health.json");
  try {
    await writeFile(path, JSON.stringify({ ...health, configuredGovernedProposalRoles: [] }));
    await assert.rejects(run(process.execPath, [cli, path, plan]),
    (error) => error.code === 2 && JSON.parse(error.stdout).actorJourney === "not-run");
    await writeFile(path, JSON.stringify(health));
    const { stdout } = await run(process.execPath, [cli, path, plan]);
    assert.equal(JSON.parse(stdout).requestedPortsConfigured, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
