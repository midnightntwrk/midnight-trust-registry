import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

import { synchronizeProvingKeys } from "./proving-key-cache.mjs";

test("Quality covers every proving-key shard exactly once", () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const workflow = yaml.load(readFileSync(join(root, ".github/workflows/quality.yaml"), "utf8"));
  const job = workflow.jobs["proving-keys"];
  const shards = job.strategy.matrix.shard;
  assert.ok(shards.length >= 2);
  assert.deepEqual(shards, Array.from({ length: shards.length }, (_, index) => index));
  const verify = job.steps.find((step) => step.name === "Verify and complete shard proving keys");
  assert.equal(verify.run, `node scripts/proving-key-cache.mjs \${{ matrix.shard }} ${shards.length}`);
  assert.equal(job.needs, "quality");
  assert.equal(job.if, "needs.quality.outputs.proving_required == 'true'");
});

test("reuses matching circuits and regenerates only changed or corrupted keys", () => {
  const root = mkdtempSync(join(tmpdir(), "tr-proving-cache-"));
  try {
    const zkirDir = join(root, "zkir");
    const keyDir = join(root, "keys");
    const distKeyDir = join(root, "dist-keys");
    mkdirSync(zkirDir);
    writeFileSync(join(zkirDir, "first.zkir"), "first-v1");
    writeFileSync(join(zkirDir, "second.zkir"), "second-v1");
    const compiled = [];
    const input = {
      zkirDir, keyDir, distKeyDir, compactVersion: "0.31.1", zkirVersion: "zkir 0.31.1",
      compile: (path, prover, verifier) => {
        compiled.push(path);
        const data = readFileSync(path, "utf8");
        writeFileSync(prover, `prover:${data}`);
        writeFileSync(verifier, `verifier:${data}`);
      },
    };
    assert.deepEqual(synchronizeProvingKeys(input), { total: 2, reused: 0, generated: 2 });
    assert.deepEqual(synchronizeProvingKeys(input), { total: 2, reused: 2, generated: 0 });
    assert.equal(readFileSync(join(distKeyDir, "first.prover"), "utf8"), "prover:first-v1");

    writeFileSync(join(zkirDir, "first.zkir"), "first-v2");
    assert.deepEqual(synchronizeProvingKeys(input), { total: 2, reused: 1, generated: 1 });
    assert.equal(compiled.length, 3);

    writeFileSync(join(keyDir, "second.verifier"), "corrupted");
    assert.deepEqual(synchronizeProvingKeys(input), { total: 2, reused: 1, generated: 1 });
    assert.equal(readFileSync(join(keyDir, "second.verifier"), "utf8"), "verifier:second-v1");

    assert.deepEqual(synchronizeProvingKeys({ ...input, zkirVersion: "zkir 0.31.2" }),
      { total: 2, reused: 0, generated: 2 });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("fails closed when no ZKIR circuits are available", () => {
  const root = mkdtempSync(join(tmpdir(), "tr-proving-empty-"));
  try {
    assert.throws(() => synchronizeProvingKeys({
      zkirDir: root, keyDir: join(root, "keys"), compactVersion: "0.31.1", zkirVersion: "zkir 0.31.1",
      compile: () => assert.fail("no circuit should compile"),
    }), /No generated ZKIR/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("shards cover every circuit once and reuse only matching key pairs", () => {
  const root = mkdtempSync(join(tmpdir(), "tr-proving-shards-"));
  try {
    const zkirDir = join(root, "zkir");
    mkdirSync(zkirDir);
    for (const name of ["alpha", "beta", "gamma", "delta", "epsilon"]) {
      writeFileSync(join(zkirDir, `${name}.zkir`), name);
    }
    const compiled = [];
    const input = {
      zkirDir, compactVersion: "0.31.1", zkirVersion: "zkir 0.31.1", shardCount: 2,
      compile: (path, prover, verifier) => {
        compiled.push(path);
        const data = readFileSync(path, "utf8");
        writeFileSync(prover, `prover:${data}`);
        writeFileSync(verifier, `verifier:${data}`);
      },
    };
    assert.deepEqual(synchronizeProvingKeys({ ...input, shardIndex: 0, keyDir: join(root, "shard-0") }),
      { total: 3, reused: 0, generated: 3 });
    assert.deepEqual(synchronizeProvingKeys({ ...input, shardIndex: 1, keyDir: join(root, "shard-1") }),
      { total: 2, reused: 0, generated: 2 });
    assert.equal(new Set(compiled).size, 5);
    assert.deepEqual(synchronizeProvingKeys({ ...input, shardIndex: 0, keyDir: join(root, "shard-0") }),
      { total: 3, reused: 3, generated: 0 });
    writeFileSync(join(zkirDir, "delta.zkir"), "delta-v2");
    assert.deepEqual(synchronizeProvingKeys({ ...input, shardIndex: 0, keyDir: join(root, "shard-0") }),
      { total: 3, reused: 2, generated: 1 });
    assert.throws(() => synchronizeProvingKeys({ ...input, shardIndex: 2, keyDir: join(root, "bad") }),
      /Invalid proving-key shard/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
