import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { KEYLESS_KEYGEN_PARAMETER_PATHS, PROTOCOL_KEY_PATHS } from "./standalone-proof-parameter-catalog.mjs";
import { assertPrivateProtocolCacheParent, ensureMaterializedProtocolProofParams,
  verifyMaterializedProtocolProofParams } from "./materialize-standalone-proof-params.mjs";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("private cache parent may be adjacent to, but never inside, the install bundle", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-protocol-cache-parent-"));
  const bundle = join(root, "bundle");
  try {
    await mkdir(bundle, { mode: 0o700 });
    await mkdir(join(bundle, "private"), { mode: 0o700 });
    await mkdir(join(root, "outside"), { mode: 0o700 });
    await mkdir(join(root, "public"), { mode: 0o755 });
    await assertPrivateProtocolCacheParent(bundle, join(root, "cache"));
    await assertPrivateProtocolCacheParent(bundle, join(root, "outside", "cache"));
    await assert.rejects(assertPrivateProtocolCacheParent(bundle, join(bundle, "cache")),
      /must not modify the install bundle/u);
    await assert.rejects(assertPrivateProtocolCacheParent(bundle, join(bundle, "private", "cache")),
      /must not modify the install bundle/u);
    await assert.rejects(assertPrivateProtocolCacheParent(bundle, join(root, "public", "cache")),
      /private directory/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("v7 materialized protocol cache requires all pinned bytes and no extra keys", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-protocol-keyless-"));
  const bundle = join(root, "bundle");
  const cache = join(root, "cache");
  try {
    await mkdir(bundle);
    await mkdir(cache, { mode: 0o700 });
    await mkdir(join(bundle, "proof-params"));
    await mkdir(join(bundle, "keygen"));
    const generator = Buffer.from("pinned generator");
    await writeFile(join(bundle, "keygen/zkir"), generator);
    const base = [];
    const protocolKeys = {};
    for (const name of [...KEYLESS_KEYGEN_PARAMETER_PATHS, ...PROTOCOL_KEY_PATHS]) {
      const bytes = Buffer.from(`generated:${name}`);
      const target = join(cache, name);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, bytes);
      if (PROTOCOL_KEY_PATHS.includes(name)) protocolKeys[name] = sha(bytes);
      else {
        base.push({ path: name, sha256: sha(bytes) });
        const input = join(bundle, "proof-params", name);
        await mkdir(dirname(input), { recursive: true });
        await writeFile(input, bytes);
      }
    }
    const inventory = { format: "tr-standalone-install-v7",
      proofParameters: { directory: "proof-params", files: base },
      keylessRuntime: { path: "keygen/zkir", platform: "linux/arm64",
        sha256: sha(generator), protocolKeys } };
    const bytes = Buffer.from(JSON.stringify(inventory));
    await writeFile(join(bundle, "install-inventory.json"), bytes);
    const digest = sha(bytes);
    assert.equal((await verifyMaterializedProtocolProofParams(bundle, cache, digest)).fileCount, 25);
    await chmod(cache, 0o755);
    await assert.rejects(verifyMaterializedProtocolProofParams(bundle, cache, digest),
      /owned private directory/u);
    await chmod(cache, 0o700);
    assert.equal((await ensureMaterializedProtocolProofParams(bundle, cache, digest,
      async () => { throw new Error("verified cache must be reused"); })).fileCount, 25);
    const parked = join(root, "parked-cache");
    await rename(cache, parked);
    let materializations = 0;
    assert.equal((await ensureMaterializedProtocolProofParams(bundle, cache, digest,
      async () => { materializations += 1; await rename(parked, cache); })).fileCount, 25);
    assert.equal(materializations, 1);
    await assert.rejects(verifyMaterializedProtocolProofParams(bundle, cache, "0".repeat(64)),
      /inventory changed/u);
    const missing = PROTOCOL_KEY_PATHS[0];
    const original = await readFile(join(cache, missing));
    await rm(join(cache, missing));
    await assert.rejects(verifyMaterializedProtocolProofParams(bundle, cache, digest),
      /missing, extra, or renamed/u);
    await writeFile(join(cache, missing), original);
    await writeFile(join(cache, missing), "substituted key");
    await assert.rejects(verifyMaterializedProtocolProofParams(bundle, cache, digest),
      /hash mismatch/u);
    await assert.rejects(ensureMaterializedProtocolProofParams(bundle, cache, digest,
      async () => { throw new Error("tampered cache must not be regenerated"); }), /hash mismatch/u);
    await writeFile(join(cache, missing), original);
    await writeFile(join(cache, "unexpected.prover"), "extra");
    await assert.rejects(verifyMaterializedProtocolProofParams(bundle, cache, digest),
      /missing, extra, or renamed/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
