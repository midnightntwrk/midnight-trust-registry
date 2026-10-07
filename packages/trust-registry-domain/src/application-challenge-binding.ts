import { z } from "zod";

import { ApplicationEvidenceRoleSchema } from "./application-evidence.js";
import { DidSchema, HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";
import { AuthorizationScopeSchema, computeAuthorizationScopeCommitment } from "./scope.js";

const CanonicalIdentifierSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Challenge identifier must be canonical lowercase",
);

export const ApplicationChallengeBindingSchema = z.strictObject({
  registryId: CanonicalIdentifierSchema,
  applicationId: CanonicalIdentifierSchema,
  subjectDid: DidSchema.startsWith("did:midnight:"),
  evidenceVerifierDid: DidSchema,
  role: ApplicationEvidenceRoleSchema,
  policyId: CanonicalIdentifierSchema,
  policyVersion: z.string().regex(/^v[1-9][0-9]*$/u),
  scope: AuthorizationScopeSchema,
  scopeCommitment: HashHexSchema,
}).superRefine((binding, ctx) => {
  const scope = AuthorizationScopeSchema.safeParse(binding.scope);
  if (!scope.success) return;
  const commitment = HashHexSchema.safeParse(binding.scopeCommitment);
  if (!commitment.success) return;
  if (scope.data.role !== binding.role) {
    ctx.addIssue({ code: "custom", path: ["scope", "role"], message: "Scope role must match application role" });
  }
  if (scope.data.role === "maintainer" && scope.data.registryId !== binding.registryId) {
    ctx.addIssue({ code: "custom", path: ["scope", "registryId"], message: "Maintainer scope registry must match application registry" });
  }
  if (computeAuthorizationScopeCommitment(scope.data) !== commitment.data.toLowerCase()) {
    ctx.addIssue({ code: "custom", path: ["scopeCommitment"], message: "Scope commitment does not match canonical scope" });
  }
});

export type ApplicationChallengeBinding = z.infer<typeof ApplicationChallengeBindingSchema>;

export function computeApplicationChallengeBindingHash(input: ApplicationChallengeBinding): string {
  const binding = ApplicationChallengeBindingSchema.parse(input);
  return sha256Hex(JSON.stringify([
    "tr:application:challenge:v1",
    binding.registryId,
    binding.applicationId,
    binding.subjectDid,
    binding.evidenceVerifierDid,
    binding.role,
    binding.policyId,
    binding.policyVersion,
    binding.scopeCommitment.toLowerCase(),
  ]));
}
