import type { IncomingMessage } from "node:http";

import {
  ApplicationChallengeBindingSchema,
  ApplicationEvidenceSubmissionSchema,
  AuthorizedEvidenceVerifierSchema,
  HashHexSchema,
  computeApplicationChallengeBindingHash,
  type ApplicationChallengeBinding,
  type ApplicationEvidenceSignature,
  type ApplicationEvidenceSignatureVerifier,
  type ApplicationEvidenceSubmission,
  type AuthorizedEvidenceVerifier,
} from "@midnight-ntwrk/trust-registry-domain";
import { z } from "zod";

import { ApplicationChallengeService, type ApplicationChallengeStore } from "./application-challenges.js";
import {
  consumeChallengeAndSubmitApplication,
  type ApplicationPresentationContext,
  type VerifiedApplicationPresentation,
} from "./application-intake.js";

const NonceSchema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ApplicationIdSchema = z.string().trim().min(1).max(256);
const SubmissionSchema = z.strictObject({
  nonce: NonceSchema,
  challengeHash: HashHexSchema,
  presentation: z.unknown(),
});
const ReceiptSchema = z.strictObject({
  receiptId: HashHexSchema,
  evidenceCommitment: HashHexSchema,
  acceptedAt: z.string().datetime({ offset: true }),
});

export type ApplicationVpReceipt = z.infer<typeof ReceiptSchema>;

/** The embedding application owns authenticated applicant access, policy and atomic redacted persistence. */
export interface ApplicationVpHttpPort {
  challengeStore: ApplicationChallengeStore;
  /** Authenticate the caller and authorize access to this application; throw on denial. The request body is unread. */
  authorizeRequest(applicationId: string, request: IncomingMessage): Promise<void>;
  resolvePendingApplication(applicationId: string): Promise<{
    binding: ApplicationChallengeBinding;
    authorizedVerifiers: readonly AuthorizedEvidenceVerifier[];
  } | null>;
  verifyPresentation(presentation: unknown, context: ApplicationPresentationContext): Promise<VerifiedApplicationPresentation>;
  signEvidence(commitment: string): Promise<ApplicationEvidenceSignature>;
  verifyEvidenceSignature: ApplicationEvidenceSignatureVerifier;
  persistRedactedEvidence(applicationId: string, evidence: ApplicationEvidenceSubmission): Promise<ApplicationVpReceipt>;
}

export class ApplicationVpHttpError extends Error {
  constructor(readonly reason: "not-found" | "invalid-request" | "stale-policy" | "invalid-challenge" | "rejected") {
    super(reason);
    this.name = "ApplicationVpHttpError";
  }
}

function parseApplicationId(applicationId: string): string {
  const parsed = ApplicationIdSchema.safeParse(applicationId);
  if (!parsed.success || parsed.data !== applicationId) throw new ApplicationVpHttpError("invalid-request");
  return parsed.data;
}

function parseSubmission(input: unknown): z.infer<typeof SubmissionSchema> {
  const parsed = SubmissionSchema.safeParse(input);
  if (!parsed.success || typeof input !== "object" || input === null
    || !Object.prototype.hasOwnProperty.call(input, "presentation")) {
    throw new ApplicationVpHttpError("invalid-request");
  }
  return parsed.data;
}

async function resolve(port: ApplicationVpHttpPort, applicationId: string) {
  const current = await port.resolvePendingApplication(applicationId);
  if (current === null) throw new ApplicationVpHttpError("not-found");
  const binding = ApplicationChallengeBindingSchema.parse(current.binding);
  if (binding.applicationId !== applicationId) throw new ApplicationVpHttpError("stale-policy");
  const authorizedVerifiers = current.authorizedVerifiers.map((item) => AuthorizedEvidenceVerifierSchema.parse(item));
  if (!authorizedVerifiers.some((item) => item.did === binding.evidenceVerifierDid)) {
    throw new ApplicationVpHttpError("stale-policy");
  }
  return { binding, authorizedVerifiers };
}

function samePolicy(
  first: Awaited<ReturnType<typeof resolve>>,
  second: Awaited<ReturnType<typeof resolve>>,
): boolean {
  return computeApplicationChallengeBindingHash(first.binding) === computeApplicationChallengeBindingHash(second.binding)
    && JSON.stringify(first.authorizedVerifiers) === JSON.stringify(second.authorizedVerifiers);
}

export function createApplicationVpHttpService(port: ApplicationVpHttpPort, clock: () => number) {
  const challenges = new ApplicationChallengeService(port.challengeStore, clock);
  return {
    async issue(applicationIdInput: string, body: unknown) {
      const applicationId = parseApplicationId(applicationIdInput);
      if (typeof body !== "object" || body === null || Array.isArray(body)
        || Object.keys(body).length !== 0) throw new ApplicationVpHttpError("invalid-request");
      const current = await resolve(port, applicationId);
      const challenge = await challenges.issue(current.binding);
      return { applicationId, ...challenge };
    },
    async submit(applicationIdInput: string, body: unknown) {
      const applicationId = parseApplicationId(applicationIdInput);
      const request = parseSubmission(body);
      const current = await resolve(port, applicationId);
      const live = await challenges.isLive({
        binding: current.binding, nonce: request.nonce, challengeHash: request.challengeHash,
      });
      if (!live) throw new ApplicationVpHttpError("invalid-challenge");
      let persisted: ApplicationVpReceipt | undefined;
      let signedEvidence: ApplicationEvidenceSubmission | undefined;
      try {
        await consumeChallengeAndSubmitApplication({
          challengeService: challenges,
          binding: current.binding,
          expectedBinding: current.binding,
          nonce: request.nonce,
          challengeHash: request.challengeHash,
          presentation: request.presentation,
          verifyPresentation: port.verifyPresentation,
          signEvidence: port.signEvidence,
          authorizedVerifiers: current.authorizedVerifiers,
          verifyEvidenceSignature: port.verifyEvidenceSignature,
          evaluatedAt: new Date(clock()).toISOString(),
          propose: async ({ evidence }) => {
            const latest = await resolve(port, applicationId);
            if (!samePolicy(current, latest)) throw new ApplicationVpHttpError("stale-policy");
            const receipt = ReceiptSchema.parse(await port.persistRedactedEvidence(applicationId, evidence));
            if (receipt.evidenceCommitment !== evidence.commitment) throw new ApplicationVpHttpError("rejected");
            persisted = receipt;
            signedEvidence = evidence;
          },
        });
      } catch (error) {
        if (error instanceof ApplicationVpHttpError) throw error;
        throw new ApplicationVpHttpError("rejected");
      }
      if (persisted === undefined || signedEvidence === undefined) throw new ApplicationVpHttpError("rejected");
      // Only the canonical signed evidence and validated receipt cross the HTTP boundary.
      return { evidence: ApplicationEvidenceSubmissionSchema.parse(signedEvidence), receipt: persisted };
    },
  };
}
