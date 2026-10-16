import { z } from "zod";

import { canonicalizeJson } from "./canonical-json.js";
import { DidSchema, HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";

const TimestampSchema = z.string().datetime({ offset: true });
const NonzeroHashHexSchema = HashHexSchema.refine(
  (value) => !/^0x0{64}$/iu.test(value),
  "Commitment must be nonzero",
);

/** The authority controls this statement; local governance decides whether to trust it. */
export const RecognitionAuthorityAssertionSchema = z.strictObject({
  version: z.literal("tr-recognition-authority-assertion-v1"),
  targetRegistryId: ScopedIdentifierSchema,
  recognitionId: ScopedIdentifierSchema,
  authorityDid: DidSchema.startsWith("did:midnight:"),
  recognizedRegistryId: ScopedIdentifierSchema,
  scopeResourceType: ScopedIdentifierSchema,
  scopeResourceId: ScopedIdentifierSchema,
  accreditationSubmissionCommitment: NonzeroHashHexSchema,
  challengeHash: NonzeroHashHexSchema,
  issuedAt: TimestampSchema,
  expiresAt: TimestampSchema,
}).superRefine((value, ctx) => {
  const issued = Date.parse(value.issuedAt);
  const expires = Date.parse(value.expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)
    || expires <= issued || expires - issued > 24 * 60 * 60_000) {
    ctx.addIssue({ code: "custom", path: ["expiresAt"], message: "Assertion lifetime must be positive and at most 24 hours" });
  }
});

export const SignedRecognitionAuthorityAssertionSchema = z.strictObject({
  statement: RecognitionAuthorityAssertionSchema,
  proof: z.strictObject({
    verificationMethodId: z.string().regex(/^did:midnight:[^#]+#[A-Za-z0-9:._-]+$/u),
    algorithm: z.literal("jubjub-schnorr"),
    signature: z.string().regex(/^0x[0-9a-f]+$/u),
  }),
});

export type RecognitionAuthorityAssertion = z.infer<typeof RecognitionAuthorityAssertionSchema>;
export type SignedRecognitionAuthorityAssertion = z.infer<typeof SignedRecognitionAuthorityAssertionSchema>;

export const recognitionAuthorityStatementCommitment = (
  statement: RecognitionAuthorityAssertion,
): string => sha256Hex(JSON.stringify([
  "tr:recognition:authority-statement:v1",
  canonicalizeJson(RecognitionAuthorityAssertionSchema.parse(statement)),
]));

export const recognitionAuthorityEvidenceCommitment = (
  signed: SignedRecognitionAuthorityAssertion,
): string => sha256Hex(JSON.stringify([
  "tr:recognition:authority-evidence:v1",
  canonicalizeJson(SignedRecognitionAuthorityAssertionSchema.parse(signed)),
]));
