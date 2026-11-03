import type { IncomingMessage } from "node:http";

import type { MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import {
  SignedRecognitionAuthorityAssertionSchema,
  resolveGovernedRecognitionAccreditorAnchor,
  type GovernancePolicyRecord,
} from "@midnight-ntwrk/trust-registry-domain";
import type {
  RecognitionAccreditationStatusSource,
  RecognitionAccreditationSubmission,
} from "@midnight-ntwrk/trust-registry-integration";
import { z } from "zod";

import type { ApplicationChallengeStore } from "./application-challenges.js";
import { RecognitionAdmissionReceiptSchema, type RecognitionAdmissionStore } from "./file-recognition-admission.js";
import {
  RecognitionAuthorityChallengeBindingSchema,
  RecognitionAuthorityChallengeService,
  type RecognitionAuthorityChallengeBinding,
} from "./recognition-authority-challenges.js";

const IdentifierSchema = z.string().trim().min(1).max(256);
const NonceSchema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const SubmissionSchema = z.strictObject({
  nonce: NonceSchema,
  signed: SignedRecognitionAuthorityAssertionSchema,
  accreditation: z.strictObject({
    rawCredentialBody: z.string().min(1).max(16_384),
    rawPresentationBody: z.string().min(1).max(16_384),
    credentialProof: z.unknown(),
    presentationProof: z.unknown(),
  }),
});

export interface RecognitionAccreditationHttpPort {
  challengeStore: ApplicationChallengeStore;
  /** Must be the same physical store as challengeStore for atomic one-use acceptance. */
  admissionStore?: RecognitionAdmissionStore;
  /** Denials must throw RecognitionAccreditationAuthorizationDeniedError; other failures are unavailable. */
  authorizeRequest(recognitionId: string, request: IncomingMessage): Promise<void>;
  /** Must read policy and commitment from trusted current ledger state, never the applicant request. */
  resolveCurrentContext(recognitionId: string): Promise<{
    binding: RecognitionAuthorityChallengeBinding;
    governancePolicy: GovernancePolicyRecord;
    activePolicyCommitment: string;
    resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
    statusSource: RecognitionAccreditationStatusSource;
  } | null>;
}

export class RecognitionAccreditationAuthorizationDeniedError extends Error {
  constructor() {
    super("recognition accreditation forbidden");
    this.name = "RecognitionAccreditationAuthorizationDeniedError";
  }
}

export class RecognitionAccreditationHttpError extends Error {
  constructor(readonly reason: "not-found" | "invalid-request" | "rejected") {
    super(reason);
    this.name = "RecognitionAccreditationHttpError";
  }
}

/** Local/private evidence verification only; no durable admission receipt or public route by default. */
export function createRecognitionAccreditationHttpService(port: RecognitionAccreditationHttpPort, clock: () => number) {
  if (port.admissionStore !== undefined && port.admissionStore !== port.challengeStore) {
    throw new Error("Recognition challenge and admission stores must be identical");
  }
  const challenges = new RecognitionAuthorityChallengeService(port.challengeStore, clock);
  const parseId = (value: string): string => {
    const parsed = IdentifierSchema.safeParse(value);
    if (!parsed.success || parsed.data !== value) throw new RecognitionAccreditationHttpError("invalid-request");
    return parsed.data;
  };
  const current = async (recognitionId: string) => {
    const context = await port.resolveCurrentContext(recognitionId);
    if (context === null) throw new RecognitionAccreditationHttpError("not-found");
    const binding = RecognitionAuthorityChallengeBindingSchema.parse(context.binding);
    if (binding.recognitionId !== recognitionId) throw new RecognitionAccreditationHttpError("rejected");
    resolveGovernedRecognitionAccreditorAnchor({
      policy: context.governancePolicy,
      activePolicyCommitment: context.activePolicyCommitment,
      scope: {
        registryId: binding.targetRegistryId,
        recognizedRegistryId: binding.recognizedRegistryId,
        scopeResourceType: binding.scopeResourceType,
        scopeResourceId: binding.scopeResourceId,
      },
      evaluatedAtMs: clock(),
    });
    return { ...context, binding };
  };
  return {
    async accepted(recognitionIdInput: string) {
      const recognitionId = parseId(recognitionIdInput);
      if (port.admissionStore === undefined) throw new RecognitionAccreditationHttpError("not-found");
      const receipt = await port.admissionStore.readAccepted(recognitionId);
      if (receipt === null) throw new RecognitionAccreditationHttpError("not-found");
      return RecognitionAdmissionReceiptSchema.parse(receipt);
    },
    async issue(recognitionIdInput: string, body: unknown) {
      const recognitionId = parseId(recognitionIdInput);
      if (body === null || typeof body !== "object" || Array.isArray(body)
        || Object.keys(body).length !== 0) throw new RecognitionAccreditationHttpError("invalid-request");
      const context = await current(recognitionId);
      return { recognitionId, ...await challenges.issue(context.binding) };
    },
    async submit(recognitionIdInput: string, body: unknown) {
      const recognitionId = parseId(recognitionIdInput);
      const parsed = SubmissionSchema.safeParse(body);
      if (!parsed.success) throw new RecognitionAccreditationHttpError("invalid-request");
      const context = await current(recognitionId);
      try {
        const verified = await challenges.verifyAndConsumeAccreditedAssertion({
          binding: context.binding,
          nonce: parsed.data.nonce,
          signed: parsed.data.signed,
          accreditation: parsed.data.accreditation as RecognitionAccreditationSubmission,
          ...(port.admissionStore === undefined ? {} : { admissionStore: port.admissionStore }),
          readCurrentGovernance: async () => {
            const latest = await current(recognitionId);
            if (Object.keys(context.binding).some((key) =>
              latest.binding[key as keyof RecognitionAuthorityChallengeBinding]
                !== context.binding[key as keyof RecognitionAuthorityChallengeBinding])) {
              throw new Error("Recognition binding changed during accreditation verification");
            }
            return {
              governancePolicy: latest.governancePolicy,
              activePolicyCommitment: latest.activePolicyCommitment,
            };
          },
          resolver: context.resolver,
          statusSource: context.statusSource,
        });
        return {
          recognitionId,
          evidenceCommitment: verified.evidenceCommitment,
          ...(verified.receipt === undefined ? {} : { receipt: verified.receipt }),
          expiresAt: new Date(Math.min(
            verified.accreditation.expiresAtMs,
            Date.parse(verified.authority.statement.expiresAt),
          )).toISOString(),
        };
      } catch {
        throw new RecognitionAccreditationHttpError("rejected");
      }
    },
  };
}
