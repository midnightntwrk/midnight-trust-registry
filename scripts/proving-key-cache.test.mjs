import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { synchronizeProvingKeys } from "./proving-key-cache.mjs";

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
