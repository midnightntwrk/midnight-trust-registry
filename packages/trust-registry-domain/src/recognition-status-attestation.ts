import { z } from "zod";

import { canonicalizeJson } from "./canonical-json.js";
import { DidSchema, HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";

const TimestampSchema = z.string().datetime({ offset: true }).refine((value) => {
  const fraction = value.match(/\.(\d+)(?:Z|[+-]\d{2}:\d{2})$/u)?.[1];
  return fraction === undefined || fraction.length <= 3;
}, "Status attestation timestamps support millisecond precision at most");

export const RecognitionStatusAttestationSchema = z.strictObject({
  version: z.literal("tr-recognition-status-attestation-v1"),
  targetRegistryId: ScopedIdentifierSchema,
  statusRegistryId: ScopedIdentifierSchema,
  statusAuthorityDid: DidSchema.startsWith("did:midnight:"),
  statusAuthorityMethodId: z.string().regex(/^did:midnight:[^#]+#[A-Za-z0-9:._-]+$/u),
  statusHandleCommitment: HashHexSchema.regex(/^0x[0-9a-f]{64}$/u),
  challengeHash: HashHexSchema.regex(/^0x[0-9a-f]{64}$/u),
  active: z.boolean(),
  observedAt: TimestampSchema,
  expiresAt: TimestampSchema,
}).superRefine((value, ctx) => {
  if (!value.statusAuthorityMethodId.startsWith(`${value.statusAuthorityDid}#`)) {
    ctx.addIssue({ code: "custom", path: ["statusAuthorityMethodId"], message: "Status method must belong to status authority DID" });
  }
  const duration = Date.parse(value.expiresAt) - Date.parse(value.observedAt);
  if (duration <= 0 || duration > 5 * 60_000) {
    ctx.addIssue({ code: "custom", path: ["expiresAt"], message: "Status attestation lifetime must be positive and at most five minutes" });
  }
});

export const SignedRecognitionStatusAttestationSchema = z.strictObject({
  statement: RecognitionStatusAttestationSchema,
  proof: z.strictObject({
    verificationMethodId: z.string().regex(/^did:midnight:[^#]+#[A-Za-z0-9:._-]+$/u),
    algorithm: z.literal("jubjub-schnorr"),
    signature: z.string().regex(/^0x[0-9a-f]+$/u),
  }),
});

export type RecognitionStatusAttestation = z.infer<typeof RecognitionStatusAttestationSchema>;
export type SignedRecognitionStatusAttestation = z.infer<typeof SignedRecognitionStatusAttestationSchema>;

export const recognitionStatusAttestationCommitment = (input: SignedRecognitionStatusAttestation): string =>
  sha256Hex(JSON.stringify([
    "tr:recognition:signed-status-attestation:v1",
    canonicalizeJson(SignedRecognitionStatusAttestationSchema.parse(input)),
  ]));

export const recognitionStatusStatementCommitment = (input: RecognitionStatusAttestation): string =>
  sha256Hex(JSON.stringify([
    "tr:recognition:status-statement:v1",
    canonicalizeJson(RecognitionStatusAttestationSchema.parse(input)),
  ]));
