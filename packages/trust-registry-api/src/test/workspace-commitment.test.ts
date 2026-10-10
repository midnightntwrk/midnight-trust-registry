import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  applyWorkspaceOperation,
  createOperatorWorkspace,
  loadWorkspaceFromFile,
  writeWorkspaceToFile,
} from "@midnight-ntwrk/trust-registry-cli";
import { describe, expect, it } from "vitest";

import { computeOperatorWorkspaceCommitment, computeValidatedOperatorWorkspaceCommitment } from "../workspace-commitment.js";

describe("operator workspace revision commitment", () => {
  it("changes for writes within one epoch and is independent of JSON key order", () => {
    const workspace = createOperatorWorkspace({ label: "intent-revision" });
    const initialEpochId = workspace.snapshot.currentEpoch.epochId;
    const before = computeOperatorWorkspaceCommitment(workspace);
    expect(computeValidatedOperatorWorkspaceCommitment(workspace)).toBe(before);
    const reordered = Object.fromEntries(Object.entries(workspace).reverse());
    expect(computeOperatorWorkspaceCommitment(reordered as typeof workspace)).toBe(before);
    const nestedRegistry = Object.fromEntries(Object.entries(workspace.snapshot.registry).reverse());
    const nestedReordered = { ...workspace, snapshot: { ...workspace.snapshot, registry: nestedRegistry } };
    expect(computeOperatorWorkspaceCommitment(nestedReordered as typeof workspace)).toBe(before);

    const operation = {
      operation: "submit",
      target: "issuer",
      label: "intent-revision-issuer",
    } as const;
    const journalOnly = { ...workspace, operations: [...workspace.operations, operation] };
    expect(journalOnly.snapshot.currentEpoch.epochId).toBe(initialEpochId);
    expect(computeOperatorWorkspaceCommitment(journalOnly)).not.toBe(before);

    const next = applyWorkspaceOperation(workspace, operation);
    expect(computeOperatorWorkspaceCommitment(next)).not.toBe(before);

    const withUndefined = { ...workspace, operations: [...workspace.operations, { operation: "publish-epoch" as const, label: undefined }] };
    const afterJsonRoundTrip = JSON.parse(JSON.stringify(withUndefined)) as typeof withUndefined;
    expect(computeOperatorWorkspaceCommitment(withUndefined)).toBe(computeOperatorWorkspaceCommitment(afterJsonRoundTrip));

    const withUnknownProperty = { ...workspace, notPersisted: "different" };
    expect(computeOperatorWorkspaceCommitment(withUnknownProperty)).toBe(before);
  });

  it("matches the workspace writer after schema normalization", async () => {
    const workspace = createOperatorWorkspace({ label: "intent-revision" });
    const unnormalized = {
      ...workspace,
      registryLabel: " intent-revision ",
      ignoredField: "not persisted",
    } as typeof workspace;
    const directory = await mkdtemp(join(tmpdir(), "trust-registry-revision-"));
    try {
      const path = join(directory, "workspace.json");
      const before = computeOperatorWorkspaceCommitment(unnormalized);
      await writeWorkspaceToFile(path, unnormalized);
      const reloaded = await loadWorkspaceFromFile(path);
      expect(reloaded.registryLabel).toBe("intent-revision");
      expect(computeOperatorWorkspaceCommitment(reloaded)).toBe(before);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
