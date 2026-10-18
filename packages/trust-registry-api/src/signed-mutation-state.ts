import {
  MAX_CONSUMED_MUTATION_NONCES,
  TrustRegistryOperatorWorkspaceOperationSchema,
  type TrustRegistryOperatorWorkspace,
  type TrustRegistryOperatorWorkspaceOperation,
} from "@midnight-ntwrk/trust-registry-cli";
import { MutationIntentSchema, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

import { preflightMutationIntentActor } from "./mutation-intent-actor-binding.js";
import type { MutationIntentActorFailure } from "./mutation-intent-actor-binding.js";
import {
  applyIntentBoundWorkspaceOperation,
  mutationPayloadForWorkspaceOperation,
} from "./mutation-intent-preflight.js";
import { verifyMutationIntentDidSignature } from "./mutation-intent-verifier.js";

export type SignedMutationState = {
  workspace: TrustRegistryOperatorWorkspace;
  consumedNonces: Readonly<Record<string, string>>;
};

export class MutationNonceAlreadyUsedError extends Error {
  readonly code = "MUTATION_NONCE_ALREADY_USED";
  constructor() {
    super("Mutation nonce has already been consumed for this actor and registry");
    this.name = "MutationNonceAlreadyUsedError";
  }
}

export class MutationNonceCapacityExceededError extends Error {
  readonly code = "MUTATION_NONCE_CAPACITY_EXCEEDED";
  constructor() {
    super("The live signed-mutation nonce window is full");
    this.name = "MutationNonceCapacityExceededError";
  }
}

export class MutationIntentActorRejectedError extends Error {
  constructor(readonly reason: MutationIntentActorFailure) {
    super(`Signed mutation intent rejected: ${reason}`);
    this.name = "MutationIntentActorRejectedError";
  }
}

/** Pure transition; callers must persist both outputs under one cross-process atomic boundary. */
export async function transitionSignedMutationState(
  state: SignedMutationState,
  intentInput: unknown,
  signatureInput: unknown,
  operationInput: TrustRegistryOperatorWorkspaceOperation,
  now: Date,
  resolver: Parameters<typeof verifyMutationIntentDidSignature>[2],
): Promise<SignedMutationState> {
  const intent = MutationIntentSchema.parse(intentInput);
  const operation = TrustRegistryOperatorWorkspaceOperationSchema.parse(operationInput);
  const nonceKey = sha256Hex(JSON.stringify(["tr:mutation:nonce:v2", intent.registryId, intent.actorDid, intent.nonce]));
  const nowMs = now.getTime();
  const existingExpiry = state.consumedNonces[nonceKey];
  if (existingExpiry !== undefined && Date.parse(existingExpiry) > nowMs) {
    throw new MutationNonceAlreadyUsedError();
  }

  const preflight = await preflightMutationIntentActor(
    intent, signatureInput, mutationPayloadForWorkspaceOperation(operation),
    state.workspace, now, resolver,
  );
  if (!preflight.ok) throw new MutationIntentActorRejectedError(preflight.reason);

  const retained = Object.fromEntries(Object.entries(state.consumedNonces)
    .filter(([, expiry]) => Date.parse(expiry) > nowMs));
  if (Object.keys(retained).length >= MAX_CONSUMED_MUTATION_NONCES) {
    throw new MutationNonceCapacityExceededError();
  }
  const workspace = applyIntentBoundWorkspaceOperation(preflight.intent, state.workspace, operation, now);
  return { workspace, consumedNonces: { ...retained, [nonceKey]: intent.expiresAt } };
}
