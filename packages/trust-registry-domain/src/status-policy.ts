import { z } from "zod";

import { HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";

const CanonicalIdentifierSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Status policy identifiers must be lowercase",
);
const CanonicalHashSchema = HashHexSchema.regex(/^0x[0-9a-f]{64}$/u);
const VerificationMethodSchema = z.string()
  .regex(/^did:[a-z0-9]+:[^#?\s]+#[A-Za-z0-9:._-]+$/u)
  .refine(
    (value) => value === value.normalize("NFC")
      && [...value].every((char) => {
        const codePoint = char.codePointAt(0)!;
        return codePoint > 0x1f
          && (codePoint < 0x7f || codePoint > 0x9f)
          && (codePoint < 0xd800 || codePoint > 0xdfff);
      })
      && !/\p{Default_Ignorable_Code_Point}/u.test(value),
    "Status authority verification method must be an exact DID URL",
  );

export const IssuerStatusPolicyBindingSchema = z.strictObject({
  version: z.literal("tr-issuer-status-policy-v1"),
  trustRegistryId: CanonicalIdentifierSchema,
  issuerAuthorizationId: CanonicalIdentifierSchema,
  statusRegistryId: CanonicalHashSchema,
  statusAuthorityVerificationMethod: VerificationMethodSchema,
  statusPolicyId: CanonicalIdentifierSchema,
  statusPolicyVersion: z.string().regex(/^v[1-9][0-9]*$/u),
  statusPolicyContentCommitment: CanonicalHashSchema,
});

export type IssuerStatusPolicyBinding = z.infer<typeof IssuerStatusPolicyBindingSchema>;

export function canonicalizeIssuerStatusPolicyBinding(input: IssuerStatusPolicyBinding): string {
  const binding = IssuerStatusPolicyBindingSchema.parse(input);
  return JSON.stringify(binding, Object.keys(binding).sort());
}

export function computeIssuerStatusPolicyBindingCommitment(input: IssuerStatusPolicyBinding): string {
  const canonical = new TextEncoder().encode(canonicalizeIssuerStatusPolicyBinding(input));
  const domain = new TextEncoder().encode("tr:issuer-status-policy:v1");
  const preimage = new Uint8Array(domain.length + 1 + canonical.length);
  preimage.set(domain);
  preimage.set(canonical, domain.length + 1);
  return sha256Hex(preimage);
}

export function assertIssuerStatusPolicyBindingMatchesAuthorization(
  binding: IssuerStatusPolicyBinding,
  registryId: string,
  authorizationId: string,
  commitment: string,
): void {
  if (
    binding.trustRegistryId !== registryId
    || binding.issuerAuthorizationId !== authorizationId
    || computeIssuerStatusPolicyBindingCommitment(binding) !== commitment
  ) {
    throw new Error("Issuer status policy binding does not match governed authorization");
  }
}
