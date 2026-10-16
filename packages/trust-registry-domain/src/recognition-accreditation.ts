import { z } from "zod";

import { canonicalizeJson } from "./canonical-json.js";
import { DidSchema, HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";

const TimestampSchema = z.string().datetime({ offset: true }).refine((value) => {
  const fraction = value.match(/\.(\d+)(?:Z|[+-]\d{2}:\d{2})$/u)?.[1];
  return fraction === undefined || fraction.length <= 3;
}, "Recognition accreditation timestamps support millisecond precision at most");
const VersionSchema = z.string().regex(/^v[1-9][0-9]*$/u);
const MidnightDidSchema = DidSchema.startsWith("did:midnight:");
const MethodIdSchema = z.string().regex(/^did:midnight:[^#]+#[A-Za-z0-9:._-]+$/u);
const CanonicalIdSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Recognition accreditation identifiers must be canonical lowercase",
);

/** The policy preimage is governed; an applicant must not supply its trusted accreditor. */
export const RecognitionAccreditorAnchorSchema = z.strictObject({
  format: z.literal("tr-recognition-accreditor-anchor-v1"),
  targetRegistryId: CanonicalIdSchema,
  policyId: CanonicalIdSchema,
  policyVersion: VersionSchema,
  accreditorDid: MidnightDidSchema,
  accreditorAssertionMethodId: MethodIdSchema,
  credentialFamilyId: CanonicalIdSchema,
  schemaId: CanonicalIdSchema,
  statusRegistryId: CanonicalIdSchema,
  statusAuthorityDid: MidnightDidSchema,
  statusAuthorityMethodId: MethodIdSchema,
  recognizedRegistryId: CanonicalIdSchema,
  scopeResourceType: CanonicalIdSchema,
  scopeResourceId: CanonicalIdSchema,
  effectiveFrom: TimestampSchema,
  effectiveUntil: TimestampSchema,
}).superRefine((value, ctx) => {
  if (!value.accreditorAssertionMethodId.startsWith(`${value.accreditorDid}#`)) {
    ctx.addIssue({ code: "custom", path: ["accreditorAssertionMethodId"], message: "Accreditor method must belong to accreditor DID" });
  }
  if (!value.statusAuthorityMethodId.startsWith(`${value.statusAuthorityDid}#`)) {
    ctx.addIssue({ code: "custom", path: ["statusAuthorityMethodId"], message: "Status method must belong to status authority DID" });
  }
  if (Date.parse(value.effectiveUntil) <= Date.parse(value.effectiveFrom)) {
    ctx.addIssue({ code: "custom", path: ["effectiveUntil"], message: "Accreditor anchor window must be positive" });
  }
});

export const RecognitionAccreditationClaimsSchema = z.strictObject({
  version: z.literal("tr-recognition-accreditation-claims-v1"),
  authorityDid: MidnightDidSchema,
  accreditorDid: MidnightDidSchema,
  recognizedRegistryId: CanonicalIdSchema,
  scopeResourceType: CanonicalIdSchema,
  scopeResourceId: CanonicalIdSchema,
  credentialFamilyId: CanonicalIdSchema,
  schemaId: CanonicalIdSchema,
  statusRegistryId: CanonicalIdSchema,
  statusHandleCommitment: HashHexSchema.regex(/^0x[0-9a-f]{64}$/u),
  issuedAt: TimestampSchema,
  expiresAt: TimestampSchema,
}).superRefine((value, ctx) => {
  if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    ctx.addIssue({ code: "custom", path: ["expiresAt"], message: "Accreditation claims window must be positive" });
  }
});

export type RecognitionAccreditorAnchor = z.infer<typeof RecognitionAccreditorAnchorSchema>;
export type RecognitionAccreditationClaims = z.infer<typeof RecognitionAccreditationClaimsSchema>;

export const recognitionAccreditorAnchorCommitment = (input: RecognitionAccreditorAnchor): string =>
  sha256Hex(JSON.stringify([
    "tr:recognition:accreditor-anchor:v1",
    canonicalizeJson(normalizeAnchor(RecognitionAccreditorAnchorSchema.parse(input))),
  ]));

export const recognitionAccreditationClaimsCommitment = (input: RecognitionAccreditationClaims): string =>
  sha256Hex(JSON.stringify([
    "tr:recognition:accreditation-claims:v1",
    canonicalizeJson(normalizeClaims(RecognitionAccreditationClaimsSchema.parse(input))),
  ]));

function normalizeAnchor(anchor: RecognitionAccreditorAnchor): RecognitionAccreditorAnchor {
  return {
    ...anchor,
    effectiveFrom: new Date(anchor.effectiveFrom).toISOString(),
    effectiveUntil: new Date(anchor.effectiveUntil).toISOString(),
  };
}

function normalizeClaims(claims: RecognitionAccreditationClaims): RecognitionAccreditationClaims {
  return {
    ...claims,
    issuedAt: new Date(claims.issuedAt).toISOString(),
    expiresAt: new Date(claims.expiresAt).toISOString(),
  };
}

/** Pure policy/claims comparison; this does not verify a VC proof or status. */
export function assertRecognitionAccreditationClaimsMatchAnchor(input: {
  anchor: RecognitionAccreditorAnchor;
  claims: RecognitionAccreditationClaims;
  authorityDid: string;
  evaluatedAtMs: number;
}): void {
  const anchor = RecognitionAccreditorAnchorSchema.parse(input.anchor);
  const claims = RecognitionAccreditationClaimsSchema.parse(input.claims);
  if (!Number.isSafeInteger(input.evaluatedAtMs) || input.evaluatedAtMs < 0) {
    throw new Error("Recognition accreditation evaluation time is invalid");
  }
  if (
    claims.authorityDid !== input.authorityDid
    || claims.authorityDid === claims.accreditorDid
    || claims.accreditorDid !== anchor.accreditorDid
    || claims.recognizedRegistryId !== anchor.recognizedRegistryId
    || claims.scopeResourceType !== anchor.scopeResourceType
    || claims.scopeResourceId !== anchor.scopeResourceId
    || claims.credentialFamilyId !== anchor.credentialFamilyId
    || claims.schemaId !== anchor.schemaId
    || claims.statusRegistryId !== anchor.statusRegistryId
  ) {
    throw new Error("Recognition accreditation claims do not match the governed anchor");
  }
  const at = input.evaluatedAtMs;
  if (
    at < Date.parse(anchor.effectiveFrom) || at >= Date.parse(anchor.effectiveUntil)
    || at < Date.parse(claims.issuedAt) || at >= Date.parse(claims.expiresAt)
  ) {
    throw new Error("Recognition accreditation is outside its effective window");
  }
}
