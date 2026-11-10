import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it } from "vitest";

import {
  applyWorkspaceOperation,
  createOperatorWorkspace,
  ensureWorkspaceInstanceId,
  loadWorkspaceFromFile,
  writeWorkspaceToFile,
} from "../workspace.js";

it("retains a workspace instance across restart and mutation, but rotates after recreation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-guided-instance-"));
  const workspacePath = join(directory, "guided.json");
  try {
    await writeWorkspaceToFile(workspacePath, createOperatorWorkspace({ label: "guided-role-demo" }));
    const firstId = await ensureWorkspaceInstanceId(workspacePath);
    expect(await ensureWorkspaceInstanceId(workspacePath)).toBe(firstId);

    const submitted = applyWorkspaceOperation(await loadWorkspaceFromFile(workspacePath), {
      operation: "submit", target: "issuer", label: "repeated-issuer",
    });
    await writeWorkspaceToFile(workspacePath, submitted);
    expect((await loadWorkspaceFromFile(workspacePath)).workspaceInstanceId).toBe(firstId);

    await writeWorkspaceToFile(workspacePath, createOperatorWorkspace({ label: "guided-role-demo" }));
    const secondId = await ensureWorkspaceInstanceId(workspacePath);
    expect(secondId).not.toBe(firstId);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
