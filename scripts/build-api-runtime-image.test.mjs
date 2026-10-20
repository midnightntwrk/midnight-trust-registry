import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { apiPayloadInventory, assertArchiveMatchesCommit, assertLightApiPayload, stripPublishedDidProofArtifacts,
  validateApiImageInput } from "./build-api-runtime-image.mjs";

const base = `docker.io/library/node@sha256:${"a".repeat(64)}`;
const revision = "b".repeat(40);
const fingerprint = "C".repeat(40);

test("API image input requires pinned external signed build evidence", () => {
  assert.doesNotThrow(() => validateApiImageInput(base, "linux/arm64", "/tmp/tr-api-image",
    revision, fingerprint));
  for (const input of [
    ["node:24-bookworm-slim", "linux/arm64", "/tmp/tr-api-image", revision, fingerprint],
    [base, "linux/ppc64le", "/tmp/tr-api-image", revision, fingerprint],
    [base, "linux/arm64", "relative-output", revision, fingerprint],
    [base, "linux/arm64", "/tmp/tr-api-image", "wrong", fingerprint],
    [base, "linux/arm64", "/tmp/tr-api-image", revision, "wrong"],
  ]) assert.throws(() => validateApiImageInput(...input));
});

test("API payload contains runtime code but no proving keys", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-api-payload-test-"));
  try {
    const app = join(root, "app");
    const contract = join(app, "node_modules/@midnight-ntwrk/trust-registry-contract/dist/managed/trust-registry");
    await mkdir(join(app, "bin"), { recursive: true });
    await mkdir(join(app, "dist"), { recursive: true });
    await mkdir(join(contract, "contract"), { recursive: true });
    await writeFile(join(app, "package.json"), JSON.stringify({ name: "@midnight-ntwrk/trust-registry-api" }));
    for (const path of [join(app, "bin/trust-registry-api.mjs"), join(app, "dist/cli.js"),
      join(app, "dist/local-ledger-runtime.js"), join(contract, "contract/index.js")]) {
      await writeFile(path, "export {};\n");
    }
    await assertLightApiPayload(root);
    const initial = await apiPayloadInventory(root);
    assert.match(initial.sha256, /^[0-9a-f]{64}$/u);
    await mkdir(join(contract, "keys"));
    await assert.rejects(apiPayloadInventory(root), /proving-artifact directory/u);
    await rm(join(contract, "keys"), { recursive: true });
    await symlink("/tmp", join(app, "outside"));
    await assert.rejects(apiPayloadInventory(root), /external link/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("known published DID proof assets are removed from isolated staging only", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-api-did-payload-test-"));
  try {
    const did = join(root, "app/node_modules/@midnight-ntwrk/midnight-did-contract");
    await mkdir(join(root, "app/node_modules/.pnpm"), { recursive: true });
    for (const name of ["keys", "zkir"]) {
      await mkdir(join(did, "dist/managed/did", name), { recursive: true });
      await writeFile(join(did, "dist/managed/did", name, "example.prover"), "proof\n");
    }
    await writeFile(join(did, "package.json"), JSON.stringify({
      name: "@midnight-ntwrk/midnight-did-contract", version: "0.7.0",
    }));
    await stripPublishedDidProofArtifacts(root);
    await apiPayloadInventory(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("exported source bytes must match the signed Git blob", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-api-source-test-"));
  try {
    const bytes = Buffer.from("signed content\n");
    const hash = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
    const tree = `100644 blob ${hash}\tfile.txt\0`;
    await writeFile(join(root, "file.txt"), bytes);
    assert.equal(await assertArchiveMatchesCommit(root, tree), 1);
    await writeFile(join(root, "file.txt"), "changed\n");
    await assert.rejects(assertArchiveMatchesCommit(root, tree), /differ from signed blob/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
