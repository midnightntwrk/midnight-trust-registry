import { applyWorkspaceOperation, createOperatorWorkspace, resolveWorkspaceOperationRecord } from "@midnight-ntwrk/trust-registry-cli";
import { computeMutationPayloadCommitment, type MutationIntent } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it } from "vitest";

import { applyIntentBoundWorkspaceOperation, preflightMutationIntent } from "../mutation-intent-preflight.js";
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

  it("rejects reserved maintainer targets until an executable workspace operation exists", () => {
    expect(preflightMutationIntent({
      ...intent,
      target: "maintainer",
      targetId: "maintainer:example",
    }, payload, workspace, now)).toEqual({ ok: false, reason: "unsupported-target" });

    const publish = {
      ...intent,
      actorRole: "maintainer",
      action: "publish-epoch",
      target: "epoch",
      targetId: workspace.snapshot.currentEpoch.epochId,
    };
    expect(preflightMutationIntent(publish, payload, workspace, now).ok).toBe(true);
  });

  it("binds the signed action, role target, and resulting record id to one operation", () => {
    const operation = { operation: "submit" as const, target: "issuer" as const, label: "example" };
    const expected = applyWorkspaceOperation(workspace, operation);
    const record = resolveWorkspaceOperationRecord(expected, operation);
    if (!("authorization" in record)) throw new Error("expected issuer authorization");
    const bound = { ...intent, targetId: record.authorization.authorizationId };
    expect(applyIntentBoundWorkspaceOperation(bound, workspace, operation)).toEqual(expected);
    for (const substituted of [
      { ...operation, target: "verifier" as const },
      { operation: "approve" as const, target: "issuer" as const, id: bound.targetId },
    ]) {
      expect(() => applyIntentBoundWorkspaceOperation(bound, workspace, substituted))
        .toThrow(/does not match the executable workspace operation/);
    }
    expect(() => applyIntentBoundWorkspaceOperation({ ...bound, targetId: "auth:issuer:other:v1" }, workspace, operation))
      .toThrow(/does not match the executable workspace operation/);
  });

  it("binds epoch publication to the predecessor, not the new epoch id", () => {
    const publish: MutationIntent = {
      ...intent,
      actorRole: "maintainer",
      action: "publish-epoch",
      target: "epoch",
      targetId: workspace.snapshot.currentEpoch.epochId,
    };
    const operation = { operation: "publish-epoch" as const, label: "next" };
    expect(applyIntentBoundWorkspaceOperation(publish, workspace, operation)).toEqual(
      applyWorkspaceOperation(workspace, operation),
    );
    expect(() => applyIntentBoundWorkspaceOperation({ ...publish, expectedEpochId: "epoch:stale", targetId: "epoch:stale" }, workspace, operation))
      .toThrow(/does not match the executable workspace operation/);
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
