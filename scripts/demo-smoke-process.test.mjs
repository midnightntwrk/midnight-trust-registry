import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { describeChildExit, stopChild } from "./demo-smoke-process.mjs";

const smokeScript = fileURLToPath(new URL("./demo-smoke.mjs", import.meta.url));

const fakeChild = (onKill) => {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.kill = (signal) => onKill(child, signal);
  child.unref = () => {};
  return child;
};

test("reports signal termination instead of an absent exit code", () => {
  assert.equal(describeChildExit({ exitCode: null, signalCode: "SIGTERM" }), "signal SIGTERM");
  assert.equal(describeChildExit({ exitCode: 2, signalCode: null }), "code 2");
});

test("graceful child shutdown is not reported as forced", async () => {
  const child = fakeChild((process, signal) => {
    process.signalCode = signal;
    process.emit("exit", null, signal);
  });
  assert.deepEqual(await stopChild(child, { graceMs: 5, hardMs: 20 }), { forced: false, timedOut: false });
});

test("a child that ignores SIGTERM reports forced SIGKILL", async () => {
  const signals = [];
  const child = fakeChild((process, signal) => {
    signals.push(signal);
    if (signal === "SIGKILL") {
      process.signalCode = signal;
      process.emit("exit", null, signal);
    }
  });
  assert.deepEqual(await stopChild(child, { graceMs: 5, hardMs: 30 }), { forced: true, timedOut: false });
  assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
});

test("an already-exited child is not marked forced at the grace deadline", async () => {
  const child = fakeChild((process, signal) => {
    if (signal === "SIGTERM") {
      process.exitCode = 0;
      setTimeout(() => process.emit("exit", 0, null), 10);
    } else {
      assert.fail("must not send SIGKILL to an exited child");
    }
  });
  assert.deepEqual(await stopChild(child, { graceMs: 5, hardMs: 30 }), { forced: false, timedOut: false });
});

test("hard timeout reports a potentially orphaned child", async () => {
  const child = fakeChild(() => {});
  assert.deepEqual(await stopChild(child, { graceMs: 5, hardMs: 20 }), { forced: true, timedOut: true });
});

test("requires a value for --workspace before building anything", () => {
  const result = spawnSync(process.execPath, [smokeScript, "--workspace"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /--workspace requires a path/);
});

test("never overwrites an explicit workspace file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tr-demo-workspace-"));
  const workspace = path.join(dir, "workspace.json");
  try {
    fs.writeFileSync(workspace, "user-owned\n");
    const result = spawnSync(process.execPath, [smokeScript, "--workspace", workspace], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /refusing to overwrite existing demo smoke file/);
    assert.equal(fs.readFileSync(workspace, "utf8"), "user-owned\n");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("build launch failure cleans default artifacts and reports the spawn cause", () => {
  const artifactRoot = path.resolve(path.dirname(smokeScript), "../artifacts/trust-registry/demo-smoke");
  const runs = () => fs.existsSync(artifactRoot)
    ? fs.readdirSync(artifactRoot).filter((name) => name.startsWith("run-")).sort()
    : [];
  const before = runs();
  const result = spawnSync(process.execPath, [smokeScript], {
    encoding: "utf8",
    env: { ...process.env, PATH: "/nonexistent" },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /pnpm .* failed to start/);
  assert.match(result.stderr, /spawn error:/);
  assert.doesNotMatch(result.stderr, /exit code null/);
  assert.deepEqual(runs(), before);
});

test("failed explicit workspace setup does not report a retained user directory", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tr-demo-workspace-"));
  try {
    const result = spawnSync(process.execPath, [smokeScript, "--workspace", path.join(dir, "workspace.json")], {
      encoding: "utf8",
      env: { ...process.env, PATH: "/nonexistent" },
    });
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stderr, /\[demo-smoke\] artifacts:/);
    assert.deepEqual(fs.readdirSync(dir), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
