import { describe, expect, it } from "vitest";

import {
  GovernedMembershipActionSchema,
  sameGovernedMembershipAction,
  serializeGovernedMembershipAction,
  type GovernedMembershipActionContext,
} from "../governed-membership-actions.js";

const bytes = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const context = (
  field: "authorizationId" | "maintainerId" | "recognitionId",
): GovernedMembershipActionContext => ({
  registryId: bytes(1),
  [field]: bytes(2),
  policyCommitment: bytes(3),
  actionKind: bytes(4),
  actionPayloadHash: bytes(5),
  actionSequence: 7n,
  previousLifecycleEventHash: bytes(6),
  evidenceHash: bytes(8),
});

describe("governed membership action target", () => {
  it("admits only the five signed lifecycle actions", () => {
    for (const action of ["approve", "activate", "suspend", "revoke", "archive"]) {
      expect(GovernedMembershipActionSchema.parse(action)).toBe(action);
    }
    expect(() => GovernedMembershipActionSchema.parse("delete")).toThrow();
  });

  for (const role of ["issuer", "verifier", "auditor", "maintainer", "recognition"] as const) {
    it(`serializes the actual ${role} Compact target without a role-specific alias`, () => {
      const field = role === "maintainer" ? "maintainerId"
        : role === "recognition" ? "recognitionId" : "authorizationId";
      const prepared = serializeGovernedMembershipAction(context(field), role);
      expect(prepared.targetId).toBe(`0x${"02".repeat(32)}`);
      expect(prepared).not.toHaveProperty("authorizationId");
      expect(sameGovernedMembershipAction(prepared, prepared)).toBe(true);
      expect(sameGovernedMembershipAction(prepared, { ...prepared, targetId: `0x${"09".repeat(32)}` }))
        .toBe(false);
    });
  }

  it("rejects a missing or malformed target for the requested role", () => {
    expect(() => serializeGovernedMembershipAction(context("authorizationId"), "maintainer"))
      .toThrow("Missing maintainer action target");
    expect(() => serializeGovernedMembershipAction({
      ...context("maintainerId"), maintainerId: bytes(2).subarray(1),
    }, "maintainer")).toThrow("bytes32");
  });
});
