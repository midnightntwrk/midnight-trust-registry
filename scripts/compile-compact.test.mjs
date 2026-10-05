import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pin = readFileSync(join(root, ".compact-version"), "utf8").trim();

test("compiler wrapper selects the checked-in version and preserves failures", () => {
  const fixture = mkdtempSync(join(tmpdir(), "tr-compact-wrapper-"));
  try {
    const compiler = join(fixture, "compact");
    const argsFile = join(fixture, "args");
    writeFileSync(compiler, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$COMPACT_TEST_ARGS\"\nexit \"$COMPACT_TEST_EXIT\"\n");
    chmodSync(compiler, 0o755);
    const env = {
      ...process.env,
      COMPACT_TEST_ARGS: argsFile,
      COMPACT_TEST_EXIT: "0",
      PATH: `${fixture}${delimiter}${process.env.PATH ?? ""}`,
    };
    const command = [join(root, "scripts/compile-compact.mjs"), "--skip-zk", "source.compact", "managed"];

    const success = spawnSync(process.execPath, command, { env, encoding: "utf8" });
    assert.equal(success.status, 0, success.stderr);
    assert.equal(readFileSync(argsFile, "utf8"), `compile\n+${pin}\n--skip-zk\nsource.compact\nmanaged\n`);

    const failure = spawnSync(process.execPath, command, {
      env: { ...env, COMPACT_TEST_EXIT: "7" },
      encoding: "utf8",
    });
    assert.equal(failure.status, 7);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
