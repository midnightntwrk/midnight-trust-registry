import {
  MutableSnapshotTargetSchema,
  TrustRegistryOperatorWorkspaceOperationSchema,
  applyWorkspaceOperation,
  resolveWorkspaceOperationRecord,
  type TrustRegistryOperatorWorkspace,
  type TrustRegistryOperatorWorkspaceOperation,
} from "@midnight-ntwrk/trust-registry-cli";
import {
  computeMutationPayloadCommitment,
  MutationIntentSchema,
  type MutationIntent,
} from "@midnight-ntwrk/trust-registry-domain";

import { computeOperatorWorkspaceCommitment } from "./workspace-commitment.js";

export type MutationIntentPreflightFailure =
  | "invalid-intent"
  | "invalid-clock"
  | "not-yet-valid"
  | "expired"
  | "wrong-registry"
  | "unsupported-target"
  | "stale-epoch"
  | "stale-workspace"
  | "invalid-payload"
  | "wrong-payload";

export type MutationIntentPreflightResult =
  | { ok: true; intent: MutationIntent }
  | { ok: false; reason: MutationIntentPreflightFailure };

export class MutationIntentOperationMismatchError extends Error {
  readonly code = "INTENT_OPERATION_MISMATCH";
  constructor() {
    super("Signed intent does not match the executable workspace operation");
    this.name = "MutationIntentOperationMismatchError";
  }
}

/** Run again inside the atomic write boundary; this check does not consume a nonce. */
export function preflightMutationIntent(
  intentInput: unknown,
  validatedPayload: unknown,
  workspace: TrustRegistryOperatorWorkspace,
  now: Date,
): MutationIntentPreflightResult {
  const parsed = MutationIntentSchema.safeParse(intentInput);
  if (!parsed.success) return { ok: false, reason: "invalid-intent" };
  const intent = parsed.data;
  if (intent.target !== "epoch" && !MutableSnapshotTargetSchema.safeParse(intent.target).success) {
    return { ok: false, reason: "unsupported-target" };
  }

  const nowMs = now.getTime();
  if (!Number.isFinite(nowMs)) return { ok: false, reason: "invalid-clock" };
  if (nowMs < Date.parse(intent.issuedAt)) return { ok: false, reason: "not-yet-valid" };
  if (nowMs >= Date.parse(intent.expiresAt)) return { ok: false, reason: "expired" };
  if (intent.registryId !== workspace.snapshot.registry.registryId) {
    return { ok: false, reason: "wrong-registry" };
  }
  if (intent.expectedEpochId !== workspace.snapshot.currentEpoch.epochId) {
    return { ok: false, reason: "stale-epoch" };
  }
  if (intent.expectedWorkspaceCommitment !== computeOperatorWorkspaceCommitment(workspace)) {
    return { ok: false, reason: "stale-workspace" };
  }
  try {
    if (intent.payloadCommitment !== computeMutationPayloadCommitment(validatedPayload)) {
      return { ok: false, reason: "wrong-payload" };
    }
  } catch {
    return { ok: false, reason: "invalid-payload" };
  }
  return { ok: true, intent };
}

/** Use inside an atomic write boundary after signature authorization; repeats context/payload preflight. */
export function applyIntentBoundWorkspaceOperation(
  intentInput: MutationIntent,
  workspace: TrustRegistryOperatorWorkspace,
  operationInput: TrustRegistryOperatorWorkspaceOperation,
  now: Date,
): TrustRegistryOperatorWorkspace {
  const intent = MutationIntentSchema.parse(intentInput);
  const operation = TrustRegistryOperatorWorkspaceOperationSchema.parse(operationInput);
  const target = operation.operation === "publish-epoch" ? "epoch" : operation.target;
  const payload = operation.operation === "publish-epoch"
    ? { ...(operation.label === undefined ? {} : { label: operation.label }) }
    : operation.operation === "submit"
      ? { target: operation.target, label: operation.label }
      : { target: operation.target, id: operation.id };
  if (intent.action !== operation.operation || intent.target !== target
    || (operation.operation === "publish-epoch"
      && (intent.targetId !== workspace.snapshot.currentEpoch.epochId
        || intent.expectedEpochId !== workspace.snapshot.currentEpoch.epochId))
    || (operation.operation !== "submit" && operation.operation !== "publish-epoch"
      && intent.targetId !== operation.id)) {
    throw new MutationIntentOperationMismatchError();
  }
  if (!preflightMutationIntent(intent, payload, workspace, now).ok) {
    throw new MutationIntentOperationMismatchError();
  }

  let nextWorkspace: TrustRegistryOperatorWorkspace;
  try {
    nextWorkspace = applyWorkspaceOperation(workspace, operation);
  } catch {
    throw new MutationIntentOperationMismatchError();
  }
  if (operation.operation === "publish-epoch") return nextWorkspace;
  const record = resolveWorkspaceOperationRecord(nextWorkspace, operation);
  const recordId = "authorization" in record
    ? record.authorization.authorizationId
    : "recognition" in record ? record.recognition.recognitionId : null;
  if (intent.targetId !== recordId) throw new MutationIntentOperationMismatchError();
  return nextWorkspace;
}
