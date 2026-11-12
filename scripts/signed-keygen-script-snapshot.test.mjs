import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { signedKeygenScriptSnapshot } from "./signed-keygen-script-snapshot.mjs";

const REVISION = "a".repeat(40);
const MATERIALIZER = "materialize-standalone-proof-params.mjs";
const CATALOG = "standalone-proof-parameter-catalog.mjs";

async function fixture(visit) {
  const base = await mkdtemp(join(tmpdir(), "tr-signed-keygen-snapshot-"));
  const source = join(base, "source");
  const privateRoot = join(base, "private");
  await mkdir(join(source, "scripts"), { recursive: true });
  await mkdir(privateRoot, { mode: 0o700 });
  try {
    await visit({ source, privateRoot });
  } finally {
    await rm(base, { recursive: true, force: true });
  }
}

test("mount snapshot uses signed blobs, not mutable checkout scripts", () => fixture(async ({
  source, privateRoot,
}) => {
  await writeFile(join(source, "scripts", MATERIALIZER), "unreviewed checkout bytes\n");
  const calls = [];
  const run = (_file, args) => {
    calls.push(args);
    if (args[0] === "verify-commit") return Buffer.alloc(0);
    return Buffer.from(`signed ${args[1]}\n`);
  };
  const snapshot = await signedKeygenScriptSnapshot(source, REVISION, privateRoot, run);
  assert.deepEqual(calls, [["verify-commit", REVISION],
    ["show", `${REVISION}:scripts/${MATERIALIZER}`],
    ["show", `${REVISION}:scripts/${CATALOG}`]]);
  assert.equal(await readFile(join(snapshot, MATERIALIZER), "utf8"),
    `signed ${REVISION}:scripts/${MATERIALIZER}\n`);
  assert.equal(await readFile(join(snapshot, CATALOG), "utf8"),
    `signed ${REVISION}:scripts/${CATALOG}\n`);
  await rm(snapshot, { recursive: true });
}));

test("failed signed blob lookup removes the private mount", () => fixture(async ({
  source, privateRoot,
}) => {
  const run = (_file, args) => {
    if (args[0] === "verify-commit") return Buffer.alloc(0);
    if (args[1].endsWith(CATALOG)) throw new Error("missing signed catalog");
    return Buffer.from("signed materializer\n");
  };
  await assert.rejects(signedKeygenScriptSnapshot(source, REVISION, privateRoot, run),
    /missing signed catalog/u);
  assert.deepEqual(await readdir(privateRoot), []);
}));

test("rejects an invalid revision or non-private setup directory", () => fixture(async ({
  source, privateRoot,
}) => {
  await assert.rejects(signedKeygenScriptSnapshot(source, "not-a-revision", privateRoot),
    /revision is malformed/u);
  await assert.rejects(signedKeygenScriptSnapshot(source, REVISION, source),
    /owned private setup directory/u);
  assert.deepEqual(await readdir(privateRoot), []);
}));
