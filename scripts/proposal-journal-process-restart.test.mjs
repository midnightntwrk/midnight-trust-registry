import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const worker = fileURLToPath(new URL("./proposal-journal-restart-worker.mjs", import.meta.url));

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
      const child = spawnSync(process.execPath, [worker, phase, journal, broadcasts], {
        encoding: "utf8", timeout: 15_000, maxBuffer: 1024 * 1024,
      });
      assert.equal(child.status, 0, `${phase}: ${child.stderr}`);
      assert.deepEqual(JSON.parse(child.stdout), { phase, state: expectedState });
      assert.equal(await readFile(broadcasts, "utf8"), "broadcast\n");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
