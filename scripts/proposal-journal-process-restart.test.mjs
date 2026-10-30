import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const worker = fileURLToPath(new URL("./proposal-journal-restart-worker.mjs", import.meta.url));
const runPhase = (phase, journal, broadcasts) => spawnSync(
  process.execPath, [worker, phase, journal, broadcasts],
  { encoding: "utf8", timeout: 15_000, maxBuffer: 1024 * 1024 },
);

test("durable proposal quarantine survives independent process restarts", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-proposal-restart-"));
  const journal = join(root, "journal.json");
  const broadcasts = join(root, "broadcasts.txt");
  try {
    for (const [phase, expectedState] of [
      ["reserve", "reserved"],
      ["retry", "reserved"],
      ["reconcile", "observed"],
      ["replay", "observed"],
    ]) {
      const child = runPhase(phase, journal, broadcasts);
      assert.equal(child.status, 0, `${phase}: ${child.stderr}`);
      assert.deepEqual(JSON.parse(child.stdout), { phase, state: expectedState });
      assert.equal(await readFile(broadcasts, "utf8"), "broadcast\n");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a killed process leaves its durable pre-broadcast reservation quarantined", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-proposal-crash-"));
  const journal = join(root, "journal.json");
  const broadcasts = join(root, "broadcasts.txt");
  try {
    const killed = runPhase("crash", journal, broadcasts);
    assert.equal(killed.signal, "SIGKILL", killed.stderr);
    assert.equal(killed.status, null);
    const restarted = runPhase("retry", journal, broadcasts);
    assert.equal(restarted.status, 0, restarted.stderr);
    assert.deepEqual(JSON.parse(restarted.stdout), { phase: "retry", state: "reserved" });
    await assert.rejects(readFile(broadcasts, "utf8"), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
