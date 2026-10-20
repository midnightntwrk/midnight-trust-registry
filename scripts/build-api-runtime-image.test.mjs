import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { assertLightApiPayload, validateApiImageInput } from "./build-api-runtime-image.mjs";

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
    await mkdir(join(contract, "keys"));
    await assert.rejects(assertLightApiPayload(root), /must not contain proving artifacts/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
