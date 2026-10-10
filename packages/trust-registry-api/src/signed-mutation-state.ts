import {
  TrustRegistryOperatorWorkspaceOperationSchema,
  type TrustRegistryOperatorWorkspace,
  type TrustRegistryOperatorWorkspaceOperation,
} from "@midnight-ntwrk/trust-registry-cli";
import { MutationIntentSchema } from "@midnight-ntwrk/trust-registry-domain";

import { preflightMutationIntentActor } from "./mutation-intent-actor-binding.js";
import {
  applyIntentBoundWorkspaceOperation,
  mutationPayloadForWorkspaceOperation,
  MutationIntentOperationMismatchError,
} from "./mutation-intent-preflight.js";
import { verifyMutationIntentDidSignature } from "./mutation-intent-verifier.js";

export type SignedMutationState = {
  workspace: TrustRegistryOperatorWorkspace;
  consumedNonces: readonly string[];
};

export class MutationNonceAlreadyUsedError extends Error {
  readonly code = "MUTATION_NONCE_ALREADY_USED";
  constructor() {
    super("Mutation nonce has already been consumed for this actor and registry");
    this.name = "MutationNonceAlreadyUsedError";
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
  const nonceKey = JSON.stringify([intent.registryId, intent.actorDid, intent.nonce]);
  if (state.consumedNonces.includes(nonceKey)) throw new MutationNonceAlreadyUsedError();

  const preflight = await preflightMutationIntentActor(
    intent, signatureInput, mutationPayloadForWorkspaceOperation(operation),
    state.workspace, now, resolver,
  );
  if (!preflight.ok) throw new MutationIntentOperationMismatchError();

  const workspace = applyIntentBoundWorkspaceOperation(preflight.intent, state.workspace, operation, now);
  return { workspace, consumedNonces: [...state.consumedNonces, nonceKey] };
}
