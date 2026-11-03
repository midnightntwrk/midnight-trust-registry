import type { TrustRegistryOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import type { MutationIntent } from "@midnight-ntwrk/trust-registry-domain";

import {
  preflightMutationIntent,
  type MutationIntentPreflightFailure,
} from "./mutation-intent-preflight.js";
import { verifyMutationIntentDidSignature } from "./mutation-intent-verifier.js";

export type MutationIntentActorFailure = MutationIntentPreflightFailure
  | "inactive-registry"
  | "inactive-policy"
  | "not-maintainer"
  | "invalid-signature";

export type MutationIntentActorResult =
  | { ok: true; intent: MutationIntent }
  | { ok: false; reason: MutationIntentActorFailure };

/** Snapshot-level actor check only; nonce and ledger-backed authorization still require atomic admission. */
export async function preflightMutationIntentActor(
  intentInput: unknown,
  signatureInput: unknown,
  validatedPayload: unknown,
  workspace: TrustRegistryOperatorWorkspace,
  now: Date,
  resolver: Parameters<typeof verifyMutationIntentDidSignature>[2],
): Promise<MutationIntentActorResult> {
  const preflight = preflightMutationIntent(intentInput, validatedPayload, workspace, now);
  if (!preflight.ok) return preflight;
  if (workspace.snapshot.registry.status !== "active") {
    return { ok: false, reason: "inactive-registry" };
  }
  if (workspace.snapshot.policy.status !== "active") {
    return { ok: false, reason: "inactive-policy" };
  }
  if (preflight.intent.actorRole === "maintainer"
    && !workspace.snapshot.registry.maintainerDids.includes(preflight.intent.actorDid)) {
    return { ok: false, reason: "not-maintainer" };
  }
  if (!await verifyMutationIntentDidSignature(preflight.intent, signatureInput, resolver)) {
    return { ok: false, reason: "invalid-signature" };
  }
  return preflight;
}
