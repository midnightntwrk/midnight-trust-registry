import { Buffer } from "node:buffer";

import { type MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import {
  ActorAuthenticationContextSchema,
  ApplicationChallengeBindingSchema,
  ApplicationEvidenceEvaluationTimeSchema,
  AuthorizationScopeSchema,
  HashHexSchema,
  IssuerStatusPolicyBindingSchema,
  ScopedIdentifierSchema,
  computeAuthorizationScopeCommitment,
  sha256Hex,
  type ApplicationChallengeBinding,
  type ActorAuthenticationContext,
  type AuthorizationScope,
  type IssuerStatusPolicyBinding,
} from "@midnight-ntwrk/trust-registry-domain";

import { verifyMidnightVcVpProofs, type MidnightVcVpProofMaterial } from "./midnight-vc-vp-proof.js";
import { PrivateApplicationStatusWitnessSchema,
  verifyApplicationStatusDecisionWitness,
  type PrivateApplicationStatusWitness } from "./application-status-attestation.js";

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
  statusDecisionCommitment: string;
  verifiedAt: string;
  expiresAt: string;
};
export type PrivateApplicationVpVerifierResult = ApplicationVpVerifierResult & {
  privateStatusWitness?: PrivateApplicationStatusWitness;
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
  ): Promise<{ validUntilMs: number; statusDecisionCommitment: string;
    privateStatusWitness?: PrivateApplicationStatusWitness }>;
  /** Return the scope commitment observed in verified claims, not one computed from requested scope. */
  assertRoleClaims(material: ApplicationVpMaterial): Promise<{
    claimsCommitment: string;
    scopeCommitment: string;
  }>;
};

export type QualifiedApplicationVpContext = ActorAuthenticationContext;

export type QualifiedApplicationVpFamilyAdapter<Submission> = ApplicationVpFamilyAdapter<Submission> & {
  /** Derive these values from the signed presentation body, not caller-supplied metadata. */
  assertPresentationBinding(material: ApplicationVpMaterial, expected: QualifiedApplicationVpContext & {
    subjectDid: string;
    nonce: string;
    role: AuthorizationScope["role"];
    scopeCommitment: string;
    policyId: string;
    policyVersion: string;
  }): Promise<true>;
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

type ApplicationVpInput<Submission> = {
  submission: Submission;
  nonce: string;
  expectedSubjectDid: string;
  scope: AuthorizationScope;
  evaluatedAtMs: number;
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  family: ApplicationVpFamilyAdapter<Submission>;
};

export function verifyApplicationVp<Submission>(input: ApplicationVpInput<Submission>): Promise<ApplicationVpVerifierResult> {
  return verifyApplicationVpInternal(input);
}

export function verifyQualifiedApplicationVp<Submission>(input: ApplicationVpInput<Submission> & {
  family: QualifiedApplicationVpFamilyAdapter<Submission>;
  trustContext: QualifiedApplicationVpContext;
  expectedPolicyId: string;
  expectedPolicyVersion: string;
}): Promise<ApplicationVpVerifierResult> {
  return verifyQualifiedApplicationVpInternal(input, false);
}

function verifyQualifiedApplicationVpInternal<Submission>(input: ApplicationVpInput<Submission> & {
  family: QualifiedApplicationVpFamilyAdapter<Submission>;
  trustContext: QualifiedApplicationVpContext;
  expectedPolicyId: string;
  expectedPolicyVersion: string;
}, retainPrivateStatusWitness: boolean): Promise<PrivateApplicationVpVerifierResult> {
  const trusted = ActorAuthenticationContextSchema.safeParse(input.trustContext);
  const policyId = ScopedIdentifierSchema.safeParse(input.expectedPolicyId);
  if (!trusted.success || !policyId.success || policyId.data !== policyId.data.toLowerCase()
    || typeof input.expectedPolicyVersion !== "string" || !/^v[1-9][0-9]*$/u.test(input.expectedPolicyVersion)) {
    throw new ApplicationVpVerificationError("invalid_presentation");
  }
  return verifyApplicationVpInternal(input, trusted.data, {
    policyId: policyId.data,
    policyVersion: input.expectedPolicyVersion,
  }, retainPrivateStatusWitness);
}

async function verifyApplicationVpInternal<Submission>(input: ApplicationVpInput<Submission>,
  trustContext?: QualifiedApplicationVpContext,
  expectedPolicy?: { policyId: string; policyVersion: string },
  retainPrivateStatusWitness = false): Promise<PrivateApplicationVpVerifierResult> {
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
    if (trustContext !== undefined) {
      if (expectedPolicy === undefined) throw new Error("Qualified VP policy is missing");
      const parsed = ActorAuthenticationContextSchema.parse(trustContext);
      const qualifiedFamily = input.family as QualifiedApplicationVpFamilyAdapter<Submission>;
      if (typeof qualifiedFamily.assertPresentationBinding !== "function"
        || await qualifiedFamily.assertPresentationBinding(material, {
          ...parsed,
          subjectDid: input.expectedSubjectDid,
          nonce: input.nonce,
          role: scope.data.role,
          scopeCommitment: computeAuthorizationScopeCommitment(scope.data),
          policyId: expectedPolicy.policyId,
          policyVersion: expectedPolicy.policyVersion,
        }) !== true) {
        throw new Error("Presentation is not bound to the trusted registry context");
      }
    }
    presentationHash = verified.presentationHash;
  } catch (error) {
    if (error instanceof ApplicationVpDependencyUnavailableError) {
      throw new ApplicationVpVerificationError("unavailable");
    }
    throw new ApplicationVpVerificationError("invalid_presentation");
  }

  let status: { validUntilMs: number; statusDecisionCommitment: string;
    privateStatusWitness?: PrivateApplicationStatusWitness };
  let statusDecisionCommitment: string;
  let claimsCommitment: string;
  try {
    const binding = IssuerStatusPolicyBindingSchema.parse(
      await input.family.assertIssuerEligible(material, scope.data),
    );
    if (trustContext !== undefined && binding.trustRegistryId !== trustContext.registryId) {
      throw new ApplicationVpVerificationError("ineligible");
    }
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
    statusDecisionCommitment = HashHexSchema.parse(status.statusDecisionCommitment).toLowerCase();
    if (status.privateStatusWitness !== undefined) {
      const witness = PrivateApplicationStatusWitnessSchema.parse(status.privateStatusWitness);
      if (witness.nonce !== input.nonce) throw new ApplicationVpVerificationError("ineligible");
      await verifyApplicationStatusDecisionWitness({
        signed: witness.signed,
        material,
        binding,
        nonce: witness.nonce,
        expectedChallengeHash: `0x${expectedChallengeHash.toString("hex")}`,
        expectedCommitment: statusDecisionCommitment,
        evaluatedAtMs: input.evaluatedAtMs,
        resolver: guardedResolver,
      });
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
    statusDecisionCommitment,
    verifiedAt: new Date(input.evaluatedAtMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    ...(!retainPrivateStatusWitness || status.privateStatusWitness === undefined
      ? {} : { privateStatusWitness: status.privateStatusWitness }),
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

/** The qualified host pins its own audience and deployment before accepting any VP. */
export function createQualifiedApplicationVpIntakeVerifier<Submission>(config: {
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  family: QualifiedApplicationVpFamilyAdapter<Submission>;
  trustContext: QualifiedApplicationVpContext;
}): (presentation: unknown, context: {
  nonce: string;
  binding: ApplicationChallengeBinding;
  evaluatedAt: string;
}) => Promise<PrivateApplicationVpVerifierResult> {
  const trusted = ActorAuthenticationContextSchema.parse(config.trustContext);
  return async (presentation, context) => {
    let binding: ApplicationChallengeBinding;
    try {
      binding = ApplicationChallengeBindingSchema.parse(context.binding);
      ApplicationEvidenceEvaluationTimeSchema.parse(context.evaluatedAt);
      if (binding.registryId !== trusted.registryId) throw new Error("Registry differs from trusted deployment");
    } catch {
      throw new ApplicationVpVerificationError("invalid_presentation");
    }
    return verifyQualifiedApplicationVpInternal({
      resolver: config.resolver,
      family: config.family,
      trustContext: trusted,
      expectedPolicyId: binding.policyId,
      expectedPolicyVersion: binding.policyVersion,
      submission: presentation as Submission,
      nonce: context.nonce,
      expectedSubjectDid: binding.subjectDid,
      scope: binding.scope,
      evaluatedAtMs: Date.parse(context.evaluatedAt),
    }, true);
  };
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function validTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && Number.isFinite(new Date(value).getTime());
}
