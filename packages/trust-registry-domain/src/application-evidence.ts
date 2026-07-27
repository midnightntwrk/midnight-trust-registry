import { z } from "zod";

import { DidSchema, HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";
import { AuthorizationRoleSchema } from "./types.js";

const TimestampSchema = z.string().datetime({ offset: true });
const NonEmptyStringSchema = z.string().trim().min(1);
const KeyReferenceSchema = z
  .string()
  .regex(/^did:[^#]+#[A-Za-z0-9:._-]+$/, "Key references must be DID fragments");

export const ApplicationEvidenceRoleSchema = AuthorizationRoleSchema.exclude([
  "authority",
]);

export const ApplicationEvidenceEnvelopeSchema = z
  .object({
    version: z.literal("tr-application-evidence-v1"),
    registryId: ScopedIdentifierSchema,
    applicationId: ScopedIdentifierSchema,
    subjectDid: DidSchema.startsWith("did:midnight:"),
    role: ApplicationEvidenceRoleSchema,
    policyId: ScopedIdentifierSchema,
    policyVersion: NonEmptyStringSchema,
    scopeCommitment: HashHexSchema,
    evidenceVerifierDid: DidSchema,
    verifiedAt: TimestampSchema,
    expiresAt: TimestampSchema,
    challengeHash: HashHexSchema,
    presentationHash: HashHexSchema,
    claimsCommitment: HashHexSchema,
  })
  .superRefine((envelope, ctx) => {
    if (Date.parse(envelope.expiresAt) <= Date.parse(envelope.verifiedAt)) {
      ctx.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "expiresAt must be later than verifiedAt",
      });
    }
  });

export const ApplicationEvidenceSignatureSchema = z.object({
  keyId: KeyReferenceSchema,
  algorithm: z.enum(["jubjub-schnorr", "secp256k1", "secp256r1", "ed25519"]),
  value: NonEmptyStringSchema,
});

export const ApplicationEvidenceSubmissionSchema = z.object({
  envelope: ApplicationEvidenceEnvelopeSchema,
  commitment: HashHexSchema,
  signature: ApplicationEvidenceSignatureSchema,
});

export const AuthorizedEvidenceVerifierSchema = z.object({
  did: DidSchema,
  keyIds: z.array(KeyReferenceSchema).min(1),
  algorithms: z.array(ApplicationEvidenceSignatureSchema.shape.algorithm).min(1),
});

export type ApplicationEvidenceEnvelope = z.infer<typeof ApplicationEvidenceEnvelopeSchema>;
export type ApplicationEvidenceRole = z.infer<typeof ApplicationEvidenceRoleSchema>;
export type ApplicationEvidenceSignature = z.infer<typeof ApplicationEvidenceSignatureSchema>;
export type ApplicationEvidenceSubmission = z.infer<typeof ApplicationEvidenceSubmissionSchema>;
export type AuthorizedEvidenceVerifier = z.infer<typeof AuthorizedEvidenceVerifierSchema>;

export type ApplicationEvidenceExpectation = {
  registryId: string;
  subjectDid: string;
  role: ApplicationEvidenceEnvelope["role"];
  policyId: string;
  policyVersion: string;
  scopeCommitment: string;
  evaluatedAt: string;
};

export type ApplicationEvidenceSignatureVerifier = (
  commitment: string,
  signature: ApplicationEvidenceSignature,
  verifier: AuthorizedEvidenceVerifier,
) => boolean;

/** Canonicalizes the envelope before it is committed with SHA-256. */
export function canonicalizeApplicationEvidence(
  envelope: ApplicationEvidenceEnvelope,
): string {
  return canonicalizeJson(ApplicationEvidenceEnvelopeSchema.parse(envelope));
}

export function computeApplicationEvidenceCommitment(
  envelope: ApplicationEvidenceEnvelope,
): string {
  return sha256Hex(canonicalizeApplicationEvidence(envelope));
}

export function assertValidApplicationEvidence(
  submission: ApplicationEvidenceSubmission,
  expectation: ApplicationEvidenceExpectation,
  authorizedVerifiers: readonly AuthorizedEvidenceVerifier[],
  verifySignature: ApplicationEvidenceSignatureVerifier,
): ApplicationEvidenceSubmission {
  const parsed = ApplicationEvidenceSubmissionSchema.parse(submission);
  const expectedCommitment = computeApplicationEvidenceCommitment(parsed.envelope);
  if (parsed.commitment !== expectedCommitment) {
    throw new Error("Application evidence commitment does not match its envelope");
  }

  assertEqual("registryId", parsed.envelope.registryId, expectation.registryId);
  assertEqual("subjectDid", parsed.envelope.subjectDid, expectation.subjectDid);
  assertEqual("role", parsed.envelope.role, expectation.role);
  assertEqual("policyId", parsed.envelope.policyId, expectation.policyId);
  assertEqual("policyVersion", parsed.envelope.policyVersion, expectation.policyVersion);
  assertEqual("scopeCommitment", parsed.envelope.scopeCommitment, expectation.scopeCommitment);

  if (Date.parse(expectation.evaluatedAt) >= Date.parse(parsed.envelope.expiresAt)) {
    throw new Error("Application evidence is expired at the governed transition");
  }

  const verifier = authorizedVerifiers.find(
    (candidate) => candidate.did === parsed.envelope.evidenceVerifierDid,
  );
  if (verifier === undefined) {
    throw new Error("Application evidence verifier is not authorized by policy");
  }
  if (!verifier.keyIds.includes(parsed.signature.keyId)) {
    throw new Error("Application evidence signature key is not authorized by policy");
  }
  if (!verifier.algorithms.includes(parsed.signature.algorithm)) {
    throw new Error("Application evidence signature algorithm is not authorized by policy");
  }
  if (!verifySignature(parsed.commitment, parsed.signature, verifier)) {
    throw new Error("Application evidence signature is invalid");
  }

  return parsed;
}

function assertEqual(field: string, actual: string, expected: string): void {
  if (actual !== expected) {
    throw new Error(`Application evidence ${field} does not match the governed authorization`);
  }
}

function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Application evidence cannot contain non-finite numbers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(record[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("Application evidence must contain JSON values only");
}
