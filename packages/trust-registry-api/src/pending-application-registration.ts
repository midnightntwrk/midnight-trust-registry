import type { TrustRegistryOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import {
  ApplicationChallengeBindingSchema,
  SignedPendingApplicationSchema,
  computeAuthorizationScopeCommitment,
  pendingApplicationMutationPayload,
  type SignedPendingApplication,
} from "@midnight-ntwrk/trust-registry-domain";
import { z } from "zod";

import { preflightMutationIntentActor } from "./mutation-intent-actor-binding.js";
import type { MutationIntentActorFailure } from "./mutation-intent-actor-binding.js";
import { verifyMutationIntentDidSignature } from "./mutation-intent-verifier.js";

export const PendingApplicationRecordSchema = z.strictObject({
  authorizationId: z.string().trim().min(1).max(256),
  binding: ApplicationChallengeBindingSchema,
  status: z.literal("pending"),
  createdAt: z.string().datetime({ offset: true }),
});

export type PendingApplicationRecord = z.infer<typeof PendingApplicationRecordSchema>;

export type PendingApplicationRegistrationState = {
  workspace: TrustRegistryOperatorWorkspace;
  applications: readonly PendingApplicationRecord[];
  consumedNonces: readonly string[];
};

/** The host owns atomic persistence and must use the same pending records for VP intake. */
export interface PendingApplicationRegistrationPort {
  register(request: SignedPendingApplication, now: Date): Promise<PendingApplicationRecord>;
}

export class PendingApplicationRegistrationRejectedError extends Error {
  constructor(readonly reason: MutationIntentActorFailure | "duplicate-application" | "duplicate-authorization" | "duplicate-scope" | "nonce-used") {
    super(`Pending application registration rejected: ${reason}`);
    this.name = "PendingApplicationRegistrationRejectedError";
  }
}

/** Pure transition; the host must atomically persist the returned state and recheck its workspace revision. */
export async function transitionPendingApplicationRegistration(
  state: PendingApplicationRegistrationState,
  requestInput: unknown,
  trustedEvidenceVerifierDid: string,
  now: Date,
  resolver: Parameters<typeof verifyMutationIntentDidSignature>[2],
): Promise<PendingApplicationRegistrationState> {
  const request = SignedPendingApplicationSchema.parse(requestInput);
  const intent = request.intent;
  const nonceKey = JSON.stringify([intent.registryId, intent.actorDid, intent.nonce]);
  if (state.consumedNonces.includes(nonceKey)) {
    throw new PendingApplicationRegistrationRejectedError("nonce-used");
  }
  const preflight = await preflightMutationIntentActor(
    intent,
    request.signature,
    pendingApplicationMutationPayload({
      applicationId: request.applicationId,
      authorizationId: request.authorizationId,
      scope: request.scope,
      governedResource: request.governedResource,
    }),
    state.workspace,
    now,
    resolver,
  );
  if (!preflight.ok) throw new PendingApplicationRegistrationRejectedError(preflight.reason);

  const binding = ApplicationChallengeBindingSchema.parse({
    registryId: state.workspace.snapshot.registry.registryId,
    applicationId: request.applicationId,
    subjectDid: intent.actorDid,
    evidenceVerifierDid: trustedEvidenceVerifierDid,
    role: request.scope.role,
    policyId: state.workspace.snapshot.policy.policyId,
    policyVersion: state.workspace.snapshot.policy.version,
    scope: request.scope,
    scopeCommitment: computeAuthorizationScopeCommitment(request.scope),
    governedResource: request.governedResource,
  });
  if (state.applications.some((record) => record.binding.applicationId === binding.applicationId)) {
    throw new PendingApplicationRegistrationRejectedError("duplicate-application");
  }
  if (state.applications.some((record) => record.status === "pending"
    && record.binding.registryId === binding.registryId
    && record.binding.role === binding.role
    && record.authorizationId === request.authorizationId)) {
    throw new PendingApplicationRegistrationRejectedError("duplicate-authorization");
  }
  if (state.applications.some((record) => record.status === "pending"
    && record.binding.registryId === binding.registryId
    && record.binding.subjectDid === binding.subjectDid
    && record.binding.scopeCommitment === binding.scopeCommitment
    && record.binding.governedResource.type === binding.governedResource.type
    && record.binding.governedResource.id === binding.governedResource.id)) {
    throw new PendingApplicationRegistrationRejectedError("duplicate-scope");
  }
  return {
    workspace: state.workspace,
    applications: [...state.applications, {
      authorizationId: request.authorizationId, binding, status: "pending", createdAt: now.toISOString(),
    }],
    consumedNonces: [...state.consumedNonces, nonceKey],
  };
}

/** Single-process reference only; production hosts need durable atomic persistence and live policy reads. */
export class InMemoryPendingApplicationRegistrationPort implements PendingApplicationRegistrationPort {
  private state: PendingApplicationRegistrationState;
  private tail: Promise<void> = Promise.resolve();

  constructor(
    initialState: PendingApplicationRegistrationState,
    private readonly evidenceVerifierDid: string,
    private readonly resolver: Parameters<typeof verifyMutationIntentDidSignature>[2],
  ) {
    this.state = initialState;
  }

  register(request: SignedPendingApplication, now: Date): Promise<PendingApplicationRecord> {
    const attempt = this.tail.then(async () => {
      this.state = await transitionPendingApplicationRegistration(
        this.state, request, this.evidenceVerifierDid, now, this.resolver,
      );
      return structuredClone(this.state.applications.at(-1)!);
    });
    this.tail = attempt.then(() => {}, () => {});
    return attempt;
  }

  readPending(applicationId: string): PendingApplicationRecord | null {
    const record = this.state.applications.find((item) => item.binding.applicationId === applicationId);
    return record === undefined ? null : structuredClone(record);
  }
}
