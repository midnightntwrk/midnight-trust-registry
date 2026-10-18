import {
  MAX_CONSUMED_MUTATION_NONCES,
  MAX_CONSUMED_MUTATION_NONCES_PER_ACTOR,
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
  consumedNonces: Readonly<TrustRegistryOperatorWorkspace["consumedMutationNonces"]>;
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

export class MutationActorNonceCapacityExceededError extends Error {
  readonly code = "MUTATION_ACTOR_NONCE_CAPACITY_EXCEEDED";
  constructor() {
    super("The actor's live signed-mutation nonce window is full");
    this.name = "MutationActorNonceCapacityExceededError";
  }
}

export class MutationNonceClockRollbackError extends Error {
  readonly code = "MUTATION_NONCE_CLOCK_ROLLBACK";
  constructor() {
    super("Clock moved behind the last persisted mutation nonce transition");
    this.name = "MutationNonceClockRollbackError";
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
  const actorKey = sha256Hex(JSON.stringify(["tr:mutation:actor:v1", intent.registryId, intent.actorDid]));
  const nowMs = now.getTime();
  if (state.workspace.mutationNonceClock !== null
    && nowMs < Date.parse(state.workspace.mutationNonceClock)) {
    throw new MutationNonceClockRollbackError();
  }
  const existing = state.consumedNonces[nonceKey];
  if (existing !== undefined && Date.parse(existing.expiresAt) > nowMs) {
    throw new MutationNonceAlreadyUsedError();
  }

  const preflight = await preflightMutationIntentActor(
    intent, signatureInput, mutationPayloadForWorkspaceOperation(operation),
    state.workspace, now, resolver,
  );
  if (!preflight.ok) throw new MutationIntentActorRejectedError(preflight.reason);

  const retained = Object.fromEntries(Object.entries(state.consumedNonces)
    .filter(([, entry]) => Date.parse(entry.expiresAt) > nowMs));
  if (Object.values(retained).filter((entry) => entry.actorKey === actorKey).length
    >= MAX_CONSUMED_MUTATION_NONCES_PER_ACTOR) {
    throw new MutationActorNonceCapacityExceededError();
  }
  if (Object.keys(retained).length >= MAX_CONSUMED_MUTATION_NONCES) {
    throw new MutationNonceCapacityExceededError();
  }
  const workspace = {
    ...applyIntentBoundWorkspaceOperation(preflight.intent, state.workspace, operation, now),
    mutationNonceClock: now.toISOString(),
  };
  return { workspace, consumedNonces: { ...retained, [nonceKey]: { actorKey, expiresAt: intent.expiresAt } } };
}
