import type { TrustRegistryOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import {
  ApplicationChallengeBindingSchema,
  SignedPendingAuditorApplicationSchema,
  computeAuthorizationScopeCommitment,
  pendingAuditorApplicationMutationPayload,
  requestGovernedResourceId,
  type ApplicationChallengeBinding,
  type SignedPendingAuditorApplication,
} from "@midnight-ntwrk/trust-registry-domain";

import { preflightMutationIntentActor } from "./mutation-intent-actor-binding.js";
import type { MutationIntentActorFailure } from "./mutation-intent-actor-binding.js";
import { verifyMutationIntentDidSignature } from "./mutation-intent-verifier.js";

export type PendingAuditorApplicationRecord = {
  binding: ApplicationChallengeBinding;
  status: "pending";
  createdAt: string;
};

export type PendingAuditorRegistrationState = {
  workspace: TrustRegistryOperatorWorkspace;
  applications: readonly PendingAuditorApplicationRecord[];
  consumedNonces: readonly string[];
};

/** The host owns atomic persistence and must use the same pending records for VP intake. */
export interface PendingAuditorRegistrationPort {
  register(request: SignedPendingAuditorApplication, now: Date): Promise<PendingAuditorApplicationRecord>;
}

export class PendingAuditorRegistrationRejectedError extends Error {
  constructor(readonly reason: MutationIntentActorFailure | "duplicate-application" | "duplicate-scope" | "nonce-used") {
    super(`Pending auditor registration rejected: ${reason}`);
    this.name = "PendingAuditorRegistrationRejectedError";
  }
}

/** Pure transition; the host must atomically persist the returned state and recheck its workspace revision. */
export async function transitionPendingAuditorRegistration(
  state: PendingAuditorRegistrationState,
  requestInput: unknown,
  trustedEvidenceVerifierDid: string,
  now: Date,
  resolver: Parameters<typeof verifyMutationIntentDidSignature>[2],
): Promise<PendingAuditorRegistrationState> {
  const request = SignedPendingAuditorApplicationSchema.parse(requestInput);
  const intent = request.intent;
  const nonceKey = JSON.stringify([intent.registryId, intent.actorDid, intent.nonce]);
  if (state.consumedNonces.includes(nonceKey)) {
    throw new PendingAuditorRegistrationRejectedError("nonce-used");
  }
  const preflight = await preflightMutationIntentActor(
    intent,
    request.signature,
    pendingAuditorApplicationMutationPayload({ applicationId: request.applicationId, scope: request.scope }),
    state.workspace,
    now,
    resolver,
  );
  if (!preflight.ok) throw new PendingAuditorRegistrationRejectedError(preflight.reason);

  const binding = ApplicationChallengeBindingSchema.parse({
    registryId: state.workspace.snapshot.registry.registryId,
    applicationId: request.applicationId,
    subjectDid: intent.actorDid,
    evidenceVerifierDid: trustedEvidenceVerifierDid,
    role: "auditor",
    policyId: state.workspace.snapshot.policy.policyId,
    policyVersion: state.workspace.snapshot.policy.version,
    scope: request.scope,
    scopeCommitment: computeAuthorizationScopeCommitment(request.scope),
    governedResource: { type: "requestProfile", id: requestGovernedResourceId(request.scope) },
  });
  if (state.applications.some((record) => record.binding.applicationId === binding.applicationId)) {
    throw new PendingAuditorRegistrationRejectedError("duplicate-application");
  }
  if (state.applications.some((record) => record.status === "pending"
    && record.binding.registryId === binding.registryId
    && record.binding.subjectDid === binding.subjectDid
    && record.binding.scopeCommitment === binding.scopeCommitment)) {
    throw new PendingAuditorRegistrationRejectedError("duplicate-scope");
  }
  return {
    workspace: state.workspace,
    applications: [...state.applications, { binding, status: "pending", createdAt: now.toISOString() }],
    consumedNonces: [...state.consumedNonces, nonceKey],
  };
}

/** Single-process reference only; production hosts need durable atomic persistence and live policy reads. */
export class InMemoryPendingAuditorRegistrationPort implements PendingAuditorRegistrationPort {
  private state: PendingAuditorRegistrationState;
  private tail: Promise<void> = Promise.resolve();

  constructor(
    initialState: PendingAuditorRegistrationState,
    private readonly evidenceVerifierDid: string,
    private readonly resolver: Parameters<typeof verifyMutationIntentDidSignature>[2],
  ) {
    this.state = initialState;
  }

  register(request: SignedPendingAuditorApplication, now: Date): Promise<PendingAuditorApplicationRecord> {
    const attempt = this.tail.then(async () => {
      this.state = await transitionPendingAuditorRegistration(
        this.state, request, this.evidenceVerifierDid, now, this.resolver,
      );
      return structuredClone(this.state.applications.at(-1)!);
    });
    this.tail = attempt.then(() => {}, () => {});
    return attempt;
  }

  readPending(applicationId: string): PendingAuditorApplicationRecord | null {
    const record = this.state.applications.find((item) => item.binding.applicationId === applicationId);
    return record === undefined ? null : structuredClone(record);
  }
}
