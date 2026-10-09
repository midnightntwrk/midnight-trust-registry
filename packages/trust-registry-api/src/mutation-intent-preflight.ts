import type { TrustRegistryOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
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
  | "stale-epoch"
  | "stale-workspace"
  | "invalid-payload"
  | "wrong-payload";

export type MutationIntentPreflightResult =
  | { ok: true; intent: MutationIntent }
  | { ok: false; reason: MutationIntentPreflightFailure };

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
