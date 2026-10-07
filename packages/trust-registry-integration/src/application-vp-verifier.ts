import { Buffer } from "node:buffer";

import {
  pureCircuits,
  type ExplicitHolderBinding,
  type Proof,
  type RegistryBoundStatusBinding,
} from "@midnight-ntwrk/credential-compact";
import { resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import {
  parseMidnightDIDString,
  type MidnightDIDResolverInterface,
} from "@midnight-ntwrk/midnight-did";
import {
  AuthorizationScopeSchema,
  HashHexSchema,
  sha256Hex,
  type AuthorizationScope,
} from "@midnight-ntwrk/trust-registry-domain";

const MAX_PRESENTATION_AGE_MS = 5 * 60_000;
const MAX_ATTESTATION_AGE_MS = 5 * 60_000;
const NONCE_PATTERN = /^0x[0-9a-f]{64}$/u;

export type ApplicationVpMaterial = {
  issuerDid: string;
  issuerMethodId: string;
  subjectDid: string;
  holderMethodId: string;
  credentialProof: Proof;
  presentationProof: Proof;
  credentialBodyRoot: Uint8Array;
  presentationBodyRoot: Uint8Array;
  credentialHolderBinding: ExplicitHolderBinding;
  presentationHolderBinding: ExplicitHolderBinding;
  statusBinding: RegistryBoundStatusBinding;
  credentialExpiresAtMs: number;
};

export type ApplicationVpVerifierResult = {
  subjectDid: string;
  nonce: string;
  presentationHash: string;
  claimsCommitment: string;
  verifiedAt: string;
  expiresAt: string;
};

/** Only trusted family code may construct proof body roots or make these eligibility assertions. */
export type ApplicationVpFamilyAdapter<Submission> = {
  prepare(submission: Submission): Promise<ApplicationVpMaterial>;
  assertIssuerEligible(material: ApplicationVpMaterial, scope: AuthorizationScope): Promise<true>;
  assertStatusActive(material: ApplicationVpMaterial): Promise<{ validUntilMs: number }>;
  assertRoleClaims(material: ApplicationVpMaterial, scope: AuthorizationScope): Promise<{ claimsCommitment: string }>;
};

export class ApplicationVpVerificationError extends Error {
  constructor(readonly category: "invalid_presentation" | "ineligible" | "expired") {
    super(`Application VP ${category}`);
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
  } catch {
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
  if (!validTime(material.credentialExpiresAtMs) || material.credentialExpiresAtMs <= input.evaluatedAtMs) {
    throw new ApplicationVpVerificationError("expired");
  }
  let presentationHash: string;
  try {
    const proofTime = material.presentationProof.createdAt;
    const now = BigInt(input.evaluatedAtMs);
    if (proofTime > now || proofTime < now - BigInt(MAX_PRESENTATION_AGE_MS)) {
      throw new ApplicationVpVerificationError("expired");
    }
    if (material.credentialProof.createdAt > now) {
      throw new ApplicationVpVerificationError("invalid_presentation");
    }
  } catch (error) {
    if (error instanceof ApplicationVpVerificationError) throw error;
    throw new ApplicationVpVerificationError("invalid_presentation");
  }

  try {
    const [issuerMethod, holderMethod] = await Promise.all([
      resolveMidnightDIDMethodBinding({
        resolver: input.resolver,
        did: parseMidnightDIDString(material.issuerDid),
        verificationMethodId: material.issuerMethodId,
        relationship: "assertionMethod",
      }),
      resolveMidnightDIDMethodBinding({
        resolver: input.resolver,
        did: parseMidnightDIDString(material.subjectDid),
        verificationMethodId: material.holderMethodId,
        relationship: "authentication",
      }),
    ]);
    assertProofMethod(material.credentialProof, issuerMethod);
    assertProofMethod(material.presentationProof, holderMethod);
    requireBytes32(material.credentialBodyRoot);
    requireBytes32(material.presentationBodyRoot);
    pureCircuits.assertValidIssuanceContextProof(material.credentialBodyRoot, material.credentialProof);
    pureCircuits.assertValidPresentationContextProof(material.presentationBodyRoot, material.presentationProof);
    pureCircuits.assertMatchingExplicitHolderBindings(
      material.credentialHolderBinding,
      material.presentationHolderBinding,
    );
    pureCircuits.assertProofMatchesExplicitHolderBinding(
      material.presentationHolderBinding,
      material.presentationProof,
    );
    pureCircuits.assertValidRegistryBoundStatusBinding(material.statusBinding);
    presentationHash = sha256Hex(pureCircuits.presentationProofPayloadRoot(
      material.presentationBodyRoot,
      material.presentationProof,
    ));
  } catch {
    throw new ApplicationVpVerificationError("invalid_presentation");
  }

  let status: { validUntilMs: number };
  let claimsCommitment: string;
  try {
    if (await input.family.assertIssuerEligible(material, scope.data) !== true) {
      throw new Error("Issuer is not eligible");
    }
    status = await input.family.assertStatusActive(material);
    if (!validTime(status.validUntilMs) || status.validUntilMs <= input.evaluatedAtMs) {
      throw new ApplicationVpVerificationError("expired");
    }
    const claims = await input.family.assertRoleClaims(material, scope.data);
    claimsCommitment = HashHexSchema.parse(claims.claimsCommitment).toLowerCase();
  } catch (error) {
    if (error instanceof ApplicationVpVerificationError) throw error;
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
    presentationHash,
    claimsCommitment,
    verifiedAt: new Date(input.evaluatedAtMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
  };
}

/** Adapts proof-observed bindings to the challenge intake callback; family.prepare must parse untrusted input. */
export function createApplicationVpIntakeVerifier<Submission>(config: {
  scope: AuthorizationScope;
  evaluatedAtMs: number;
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  family: ApplicationVpFamilyAdapter<Submission>;
}): (presentation: unknown, nonce: string, subjectDid: string) => Promise<ApplicationVpVerifierResult> {
  return async (presentation, nonce, subjectDid) => verifyApplicationVp({
    ...config,
    submission: presentation as Submission,
    nonce,
    expectedSubjectDid: subjectDid,
  });
}

function assertProofMethod(
  proof: Proof,
  method: Awaited<ReturnType<typeof resolveMidnightDIDMethodBinding>>,
): void {
  if (
    !equalBytes(proof.signerVerificationMethodRef.controllerAddress.bytes, method.verificationMethodRef.controllerAddress.bytes) ||
    !equalBytes(proof.signerVerificationMethodRef.methodId, method.verificationMethodRef.methodId) ||
    proof.publicKey.x !== method.publicKey.x ||
    proof.publicKey.y !== method.publicKey.y
  ) throw new Error("Proof method does not match resolved DID method");
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function requireBytes32(value: Uint8Array): void {
  if (value.length !== 32) throw new Error("Proof body root must contain 32 bytes");
}

function validTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && Number.isFinite(new Date(value).getTime());
}
