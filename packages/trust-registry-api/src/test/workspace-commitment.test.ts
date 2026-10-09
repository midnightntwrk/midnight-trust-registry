import { applyWorkspaceOperation, createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { describe, expect, it } from "vitest";

import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

describe("operator workspace revision commitment", () => {
  it("changes for writes within one epoch and is independent of JSON key order", () => {
    const workspace = createOperatorWorkspace({ label: "intent-revision" });
    const initialEpochId = workspace.snapshot.currentEpoch.epochId;
    const before = computeOperatorWorkspaceCommitment(workspace);
    const reordered = Object.fromEntries(Object.entries(workspace).reverse());
    expect(computeOperatorWorkspaceCommitment(reordered as typeof workspace)).toBe(before);

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
  });
});
