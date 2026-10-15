import { Buffer } from "node:buffer";

import { type MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import {
  ApplicationChallengeBindingSchema,
  ApplicationEvidenceEvaluationTimeSchema,
  AuthorizationScopeSchema,
  HashHexSchema,
  IssuerStatusPolicyBindingSchema,
  computeAuthorizationScopeCommitment,
  sha256Hex,
  type ApplicationChallengeBinding,
  type AuthorizationScope,
  type IssuerStatusPolicyBinding,
} from "@midnight-ntwrk/trust-registry-domain";

import { verifyMidnightVcVpProofs, type MidnightVcVpProofMaterial } from "./midnight-vc-vp-proof.js";

const MAX_PRESENTATION_AGE_MS = 5 * 60_000;
const MAX_FUTURE_CLOCK_SKEW_MS = 60_000;
const MAX_ATTESTATION_AGE_MS = 24 * 60 * 60_000;
const NONCE_PATTERN = /^0x[0-9a-f]{64}$/u;

export type ApplicationVpMaterial = MidnightVcVpProofMaterial & {
  credentialExpiresAtMs: number;
};

export type ApplicationVpVerifierResult = {
  subjectDid: string;
  nonce: string;
  scopeCommitment: string;
  presentationHash: string;
  claimsCommitment: string;
  verifiedAt: string;
  expiresAt: string;
};

/** Only trusted family code may construct proof body roots or make these eligibility assertions. */
export type ApplicationVpFamilyAdapter<Submission> = {
  prepare(submission: Submission): Promise<ApplicationVpMaterial>;
  /** Verify family claims, holder, status, and expiry against the signed credential body root. */
  assertCredentialBodyBinding(material: ApplicationVpMaterial): Promise<true>;
  /** Return the binding from a verified active issuer grant, never from the credential alone. */
  assertIssuerEligible(material: ApplicationVpMaterial, scope: AuthorizationScope): Promise<IssuerStatusPolicyBinding>;
  assertStatusActive(
    material: ApplicationVpMaterial,
    binding: IssuerStatusPolicyBinding,
    context: { nonce: string; evaluatedAtMs: number },
  ): Promise<{ validUntilMs: number }>;
  /** Return the scope commitment observed in verified claims, not one computed from requested scope. */
  assertRoleClaims(material: ApplicationVpMaterial): Promise<{
    claimsCommitment: string;
    scopeCommitment: string;
  }>;
};

export class ApplicationVpVerificationError extends Error {
  constructor(readonly category: "invalid_presentation" | "ineligible" | "expired" | "unavailable") {
    super(`Application VP ${category}`);
  }
}

/** Trusted adapters use this for retryable resolver/status infrastructure failures. */
export class ApplicationVpDependencyUnavailableError extends Error {
  constructor() {
    super("Application VP dependency unavailable");
  }
}

export async function verifyApplicationVp<Submission>(input: {
  submission: Submission;
  nonce: string;
  expectedSubjectDid: string;
  scope: AuthorizationScope;
  evaluatedAtMs: number;
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  family: ApplicationVpFamilyAdapter<Submission>;
}): Promise<ApplicationVpVerifierResult> {
  const scope = AuthorizationScopeSchema.safeParse(input.scope);
  if (!NONCE_PATTERN.test(input.nonce) || !validTime(input.evaluatedAtMs) || !scope.success) {
    throw new ApplicationVpVerificationError("invalid_presentation");
  }
  let material: ApplicationVpMaterial;
  try {
    material = await input.family.prepare(input.submission);
  } catch (error) {
    if (error instanceof ApplicationVpDependencyUnavailableError) {
      throw new ApplicationVpVerificationError("unavailable");
    }
    throw new ApplicationVpVerificationError("invalid_presentation");
  }
  if (material === null || typeof material !== "object") {
    throw new ApplicationVpVerificationError("invalid_presentation");
  }
  const expectedChallengeHash = Buffer.from(sha256Hex(Buffer.from(input.nonce.slice(2), "hex")).slice(2), "hex");
  try {
    if (
      material.subjectDid !== input.expectedSubjectDid ||
      !equalBytes(material.presentationProof.challengeHash, expectedChallengeHash)
    ) throw new ApplicationVpVerificationError("invalid_presentation");
  } catch {
    throw new ApplicationVpVerificationError("invalid_presentation");
  }
  if (!validTime(material.credentialExpiresAtMs)) {
    throw new ApplicationVpVerificationError("invalid_presentation");
  }
  if (material.credentialExpiresAtMs <= input.evaluatedAtMs) {
    throw new ApplicationVpVerificationError("expired");
  }
  let presentationHash: string;
  try {
    const proofTime = material.presentationProof.createdAt;
    const now = BigInt(input.evaluatedAtMs);
    if (proofTime > now + BigInt(MAX_FUTURE_CLOCK_SKEW_MS)) {
      throw new ApplicationVpVerificationError("invalid_presentation");
    }
    if (proofTime < now - BigInt(MAX_PRESENTATION_AGE_MS)) {
      throw new ApplicationVpVerificationError("expired");
    }
    if (material.credentialProof.createdAt > now + BigInt(MAX_FUTURE_CLOCK_SKEW_MS)) {
      throw new ApplicationVpVerificationError("invalid_presentation");
    }
  } catch (error) {
    if (error instanceof ApplicationVpVerificationError) throw error;
    throw new ApplicationVpVerificationError("invalid_presentation");
  }

  const guardedResolver: Pick<MidnightDIDResolverInterface, "resolveResult"> = {
    resolveResult: async (did) => {
      try {
        return await input.resolver.resolveResult(did);
      } catch {
        throw new ApplicationVpDependencyUnavailableError();
      }
    },
  };
  try {
    const verified = await verifyMidnightVcVpProofs({ material, resolver: guardedResolver });
    if (await input.family.assertCredentialBodyBinding(material) !== true) {
      throw new Error("Credential body binding failed");
    }
    presentationHash = verified.presentationHash;
  } catch (error) {
    if (error instanceof ApplicationVpDependencyUnavailableError) {
      throw new ApplicationVpVerificationError("unavailable");
    }
    throw new ApplicationVpVerificationError("invalid_presentation");
  }

  let status: { validUntilMs: number };
  let claimsCommitment: string;
  try {
    const binding = IssuerStatusPolicyBindingSchema.parse(
      await input.family.assertIssuerEligible(material, scope.data),
    );
    if (`0x${Buffer.from(material.statusBinding.registryRef.registryId).toString("hex")}` !== binding.statusRegistryId) {
      throw new Error("Credential status registry differs from governed issuer policy");
    }
    status = await input.family.assertStatusActive(material, binding, {
      nonce: input.nonce,
      evaluatedAtMs: input.evaluatedAtMs,
    });
    if (!validTime(status.validUntilMs) || status.validUntilMs <= input.evaluatedAtMs) {
      throw new ApplicationVpVerificationError("expired");
    }
    const claims = await input.family.assertRoleClaims(material);
    claimsCommitment = HashHexSchema.parse(claims.claimsCommitment).toLowerCase();
    if (HashHexSchema.parse(claims.scopeCommitment).toLowerCase() !== computeAuthorizationScopeCommitment(scope.data)) {
      throw new ApplicationVpVerificationError("ineligible");
    }
  } catch (error) {
    if (error instanceof ApplicationVpVerificationError) throw error;
    if (error instanceof ApplicationVpDependencyUnavailableError) {
      throw new ApplicationVpVerificationError("unavailable");
    }
    throw new ApplicationVpVerificationError("ineligible");
  }
  const expiresAtMs = Math.min(
    material.credentialExpiresAtMs,
    status.validUntilMs,
    input.evaluatedAtMs + MAX_ATTESTATION_AGE_MS,
  );
  return {
    subjectDid: material.subjectDid,
    nonce: input.nonce,
    scopeCommitment: computeAuthorizationScopeCommitment(scope.data),
    presentationHash,
    claimsCommitment,
    verifiedAt: new Date(input.evaluatedAtMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
  };
}

/** Adapts proof-observed bindings to the challenge intake callback; family.prepare must parse untrusted input. */
export function createApplicationVpIntakeVerifier<Submission>(config: {
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  family: ApplicationVpFamilyAdapter<Submission>;
}): (presentation: unknown, context: {
  nonce: string;
  binding: ApplicationChallengeBinding;
  evaluatedAt: string;
}) => Promise<ApplicationVpVerifierResult> {
  return async (presentation, context) => {
    let binding: ApplicationChallengeBinding;
    try {
      binding = ApplicationChallengeBindingSchema.parse(context.binding);
      ApplicationEvidenceEvaluationTimeSchema.parse(context.evaluatedAt);
    } catch {
      throw new ApplicationVpVerificationError("invalid_presentation");
    }
    return verifyApplicationVp({
      ...config,
      submission: presentation as Submission,
      nonce: context.nonce,
      expectedSubjectDid: binding.subjectDid,
      scope: binding.scope,
      evaluatedAtMs: Date.parse(context.evaluatedAt),
    });
  };
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function validTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && Number.isFinite(new Date(value).getTime());
}
