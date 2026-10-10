import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { computeMutationPayloadCommitment, type MutationIntent } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it } from "vitest";

import { preflightMutationIntent } from "../mutation-intent-preflight.js";
import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

const workspace = createOperatorWorkspace({ label: "intent-preflight" });
const payload = { target: "issuer", label: "example" };
const now = new Date("2026-10-10T00:01:00.000Z");
const did = `did:midnight:testnet:${"aa".repeat(32)}`;
const intent: MutationIntent = {
  version: "tr-mutation-intent-v1",
  registryId: workspace.snapshot.registry.registryId,
  actorDid: did,
  actorKeyId: `${did}#assertion-1`,
  actorRole: "applicant",
  action: "submit",
  target: "issuer",
  targetId: "auth:issuer:example:v1",
  scopeCommitment: `0x${"11".repeat(32)}`,
  payloadCommitment: computeMutationPayloadCommitment(payload),
  nonce: `0x${"33".repeat(32)}`,
  expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
  expectedEpochId: workspace.snapshot.currentEpoch.epochId,
  issuedAt: "2026-10-10T00:00:00.000Z",
  expiresAt: "2026-10-10T00:05:00.000Z",
};

describe("mutation intent preflight", () => {
  it("accepts exact context and uses an inclusive issued-at and exclusive expiry", () => {
    expect(preflightMutationIntent(intent, payload, workspace, now)).toEqual({ ok: true, intent });
    expect(preflightMutationIntent(intent, payload, workspace, new Date(intent.issuedAt)).ok).toBe(true);
    expect(preflightMutationIntent(intent, payload, workspace, new Date(intent.expiresAt))).toEqual({ ok: false, reason: "expired" });
  });

  it("rejects malformed, future, expired, and cross-registry intents", () => {
    expect(preflightMutationIntent({ ...intent, nonce: "wrong" }, payload, workspace, now)).toEqual({ ok: false, reason: "invalid-intent" });
    expect(preflightMutationIntent(intent, payload, workspace, new Date(NaN))).toEqual({ ok: false, reason: "invalid-clock" });
    expect(preflightMutationIntent(intent, payload, workspace, new Date("2026-10-09T23:59:59.999Z"))).toEqual({ ok: false, reason: "not-yet-valid" });
    expect(preflightMutationIntent({ ...intent, registryId: "tr:registry:other" }, payload, workspace, now)).toEqual({ ok: false, reason: "wrong-registry" });
  });

  it("rejects stale epochs, workspace writes within one epoch, and substituted payloads", () => {
    expect(preflightMutationIntent({ ...intent, expectedEpochId: null }, payload, workspace, now)).toEqual({ ok: false, reason: "stale-epoch" });
    const changed = { ...workspace, operations: [...workspace.operations, { operation: "submit" as const, target: "issuer" as const, label: "other" }] };
    expect(changed.snapshot.currentEpoch.epochId).toBe(intent.expectedEpochId);
    expect(preflightMutationIntent(intent, payload, changed, now)).toEqual({ ok: false, reason: "stale-workspace" });
    expect(preflightMutationIntent(intent, { ...payload, label: "other" }, workspace, now)).toEqual({ ok: false, reason: "wrong-payload" });
    expect(preflightMutationIntent(intent, { label: undefined }, workspace, now)).toEqual({ ok: false, reason: "invalid-payload" });
  });
});
