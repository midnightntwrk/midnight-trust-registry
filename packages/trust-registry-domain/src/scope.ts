import { z } from "zod";

import { HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";

const ExactStringSchema = z.string().min(1).refine(
  (value) => value === value.trim()
    && value === value.normalize("NFC")
    && !value.includes("*")
    && !/\p{Default_Ignorable_Code_Point}/u.test(value)
    && isUnicodeScalar(value),
  "Scope values must be exact NFC text without wildcards, invisible characters, controls, or lone surrogates",
);
const CanonicalIdentifierSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Scoped identifiers must be lowercase",
);
const ExactSchemaVersionSchema = ExactStringSchema.regex(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u);
const ExactHashSchema = HashHexSchema.regex(/^0x[0-9a-f]{64}$/u);
const ExactListSchema = z.array(ExactStringSchema).superRefine((values, ctx) => {
  const seen = new Set<string>();
  for (const [index, value] of values.entries()) {
    if (seen.has(value)) {
      ctx.addIssue({ code: "custom", path: [index], message: "Scope arrays must not contain duplicate IDs" });
    }
    seen.add(value);
  }
});

const ScopeBase = {
  version: z.literal("tr-scope-v1"),
};

export const IssuerScopeSchema = z.strictObject({
  ...ScopeBase,
  role: z.literal("issuer"),
  credentialFamilyId: ExactStringSchema,
  schemaId: ExactStringSchema,
  schemaVersion: ExactSchemaVersionSchema,
  credentialDefinitionId: ExactStringSchema,
  statusMethod: ExactStringSchema,
});

const RequestScopeBase = {
  ...ScopeBase,
  requestProfileId: ExactStringSchema,
  purpose: ExactStringSchema,
  credentialScopeCommitment: ExactHashSchema,
  allowedAttributes: ExactListSchema,
  allowedPredicates: ExactListSchema,
  disclosureLevel: ExactStringSchema,
};

export const VerifierScopeSchema = z.strictObject({
  ...RequestScopeBase,
  role: z.literal("verifier"),
});

export const AuditorScopeSchema = z.strictObject({
  ...RequestScopeBase,
  role: z.literal("auditor"),
});

export const MaintainerScopeSchema = z.strictObject({
  ...ScopeBase,
  role: z.literal("maintainer"),
  registryId: CanonicalIdentifierSchema,
});

export const AuthorizationScopeSchema = z.discriminatedUnion("role", [
  IssuerScopeSchema,
  VerifierScopeSchema,
  AuditorScopeSchema,
  MaintainerScopeSchema,
]);

export type AuthorizationScope = z.infer<typeof AuthorizationScopeSchema>;
export const IssuerGovernedResourceTypeSchema = z.enum([
  "credentialFamily", "schema", "schemaVersion", "credentialDefinition", "statusMethodRequirement",
]);
export type IssuerGovernedResourceType = z.infer<typeof IssuerGovernedResourceTypeSchema>;
export const IssuerGovernedResourceIdSchema = ScopedIdentifierSchema.regex(
  /^tr:issuer-resource:v1:[0-9a-f]{64}$/u,
  "Issuer resource id must be a canonical composite issuer resource id",
);

/** V1 scopes contain only strings and string arrays, so JSON string escaping is JCS-compatible. */
export function canonicalizeAuthorizationScope(scope: AuthorizationScope): string {
  const parsed = AuthorizationScopeSchema.parse(scope);
  const normalized = "allowedAttributes" in parsed
    ? {
        ...parsed,
        allowedAttributes: [...parsed.allowedAttributes].sort(),
        allowedPredicates: [...parsed.allowedPredicates].sort(),
      }
    : parsed;
  return JSON.stringify(normalized, Object.keys(normalized).sort());
}

export function encodeAuthorizationScope(scope: AuthorizationScope): Uint8Array {
  return new TextEncoder().encode(canonicalizeAuthorizationScope(scope));
}

export function computeAuthorizationScopeCommitment(scope: AuthorizationScope): string {
  return sha256Hex(encodeAuthorizationScope(scope));
}

export function issuerGovernedResourceId(
  scope: z.infer<typeof IssuerScopeSchema>,
  type: IssuerGovernedResourceType,
): string {
  const parsedScope = IssuerScopeSchema.parse(scope);
  return issuerGovernedResourceIdFromScopeCommitment(computeAuthorizationScopeCommitment(parsedScope), type);
}

export function issuerGovernedResourceIdFromScopeCommitment(
  scopeCommitment: string,
  type: IssuerGovernedResourceType,
): string {
  const parsedType = IssuerGovernedResourceTypeSchema.parse(type);
  const parsedCommitment = ExactHashSchema.parse(scopeCommitment);
  const preimage = JSON.stringify([
    "tr:issuer-resource:v1",
    parsedType,
    parsedCommitment,
  ]);
  return IssuerGovernedResourceIdSchema.parse(`tr:issuer-resource:v1:${sha256Hex(preimage).slice(2)}`);
}

function isUnicodeScalar(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return false;
    if (code >= 0xdc00 && code <= 0xdfff) return false;
    if (code >= 0xd800 && code <= 0xdbff) {
      if (++index >= value.length) return false;
      const low = value.charCodeAt(index);
      if (low < 0xdc00 || low > 0xdfff) return false;
    }
  }
  return true;
}
