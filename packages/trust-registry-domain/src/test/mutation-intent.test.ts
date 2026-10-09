import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { computeMutationIntentDigest, MutationIntentSchema } from "../mutation-intent.js";

const intent = {
  version: "tr-mutation-intent-v1" as const,
  registryId: "tr:registry:demo",
  actorDid: "did:midnight:testnet:alice",
  actorKeyId: "did:midnight:testnet:alice#assertion-1",
  actorRole: "applicant" as const,
  action: "submit" as const,
  target: "auditor" as const,
  targetId: "auth:auditor:alice:v1",
  scopeCommitment: `0x${"11".repeat(32)}`,
  payloadCommitment: `0x${"22".repeat(32)}`,
  nonce: `0x${"33".repeat(32)}`,
  expectedWorkspaceCommitment: `0x${"44".repeat(32)}`,
  expectedEpochId: "epoch:1",
  issuedAt: "2026-10-10T00:00:00.000Z",
  expiresAt: "2026-10-10T00:05:00.000Z",
};

describe("mutation intent v1", () => {
  it("hashes a fixed, domain-separated preimage independently of object key order", () => {
    const expected = createHash("sha256").update(JSON.stringify([
      "tr:mutation:intent:v1", intent.registryId, intent.actorDid, intent.actorKeyId,
      intent.actorRole, intent.action, intent.target, intent.targetId,
      intent.scopeCommitment, intent.payloadCommitment, intent.nonce,
      intent.expectedWorkspaceCommitment, intent.expectedEpochId,
      intent.issuedAt, intent.expiresAt,
    ])).digest("hex");
    expect(computeMutationIntentDigest(intent)).toBe(`0x${expected}`);
    expect(computeMutationIntentDigest({ ...intent, targetId: "auth:auditor:other:v1" })).not.toBe(`0x${expected}`);
    expect(computeMutationIntentDigest({ ...intent, actorKeyId: "did:midnight:testnet:alice#assertion-2" })).not.toBe(`0x${expected}`);
    expect(computeMutationIntentDigest({ ...intent, payloadCommitment: `0x${"55".repeat(32)}` })).not.toBe(`0x${expected}`);
    expect(computeMutationIntentDigest({ ...intent, expectedEpochId: null })).not.toBe(`0x${expected}`);
  });

  it("rejects ambiguous or unsafe signing inputs", () => {
    const invalid = [
      { ...intent, registryId: "TR:REGISTRY:DEMO" },
      { ...intent, actorDid: "did:example:alice" },
      { ...intent, actorDid: "did:midnight:testnet:alice#key-1" },
      { ...intent, actorDid: "did:midnight:testnet:alice with space" },
      { ...intent, actorKeyId: "did:midnight:testnet:bob#assertion-1" },
      { ...intent, nonce: `0x${"AA".repeat(32)}` },
      { ...intent, issuedAt: "2026-10-10T08:00:00.000+08:00" },
      { ...intent, expiresAt: "2026-10-10T00:05:00Z" },
      { ...intent, expiresAt: "2026-10-10T00:05:00.001Z" },
      { ...intent, expiresAt: intent.issuedAt },
      { ...intent, actorRole: "applicant", action: "approve" },
      { ...intent, target: "epoch" },
      { ...intent, extra: "unsigned" },
    ];
    for (const candidate of invalid) {
      expect(MutationIntentSchema.safeParse(candidate).success).toBe(false);
    }
  });

  it("permits maintainer lifecycle and epoch intents but not applicant governance", () => {
    expect(MutationIntentSchema.safeParse({ ...intent, actorRole: "maintainer", action: "approve" }).success).toBe(true);
    expect(MutationIntentSchema.safeParse({ ...intent, actorRole: "maintainer", action: "publish-epoch", target: "epoch" }).success).toBe(true);
    expect(MutationIntentSchema.safeParse({ ...intent, actorRole: "applicant", action: "publish-epoch", target: "epoch" }).success).toBe(false);
  });
});
