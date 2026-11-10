import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

export const withOtherProcessHoldingWorkspace = async (workspacePath, operation) => {
  const child = spawn(process.execPath, [
    fileURLToPath(new URL("./hold-workspace-lock.mjs", import.meta.url)), workspacePath,
  ], { stdio: ["pipe", "pipe", "pipe"] });
  const exited = once(child, "exit", { signal: AbortSignal.timeout(10_000) });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  try {
    const [ready] = await once(child.stdout, "data", { signal: AbortSignal.timeout(5_000) });
    assert.equal(String(ready), "locked\n");
    await operation();
  } finally {
    child.stdin.end();
    const [code] = await exited;
    assert.equal(code, 0, stderr);
  }
};
