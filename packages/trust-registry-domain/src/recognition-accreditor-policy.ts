import { z } from "zod";

import { HashHexSchema, ScopedIdentifierSchema } from "./ids.js";
import {
  recognitionAccreditorAnchorCommitment,
  type RecognitionAccreditorAnchor,
} from "./recognition-accreditation.js";
import {
  computeGovernancePolicySnapshotCommitment,
  deriveGovernancePolicySnapshot,
} from "./policy-snapshot.js";
import { GovernancePolicyRecordSchema, type GovernancePolicyRecord } from "./types.js";

const ScopeSchema = z.strictObject({
  registryId: ScopedIdentifierSchema,
  recognizedRegistryId: ScopedIdentifierSchema,
  scopeResourceType: ScopedIdentifierSchema,
  scopeResourceId: ScopedIdentifierSchema,
});

/** Resolve only an anchor committed by the current on-ledger governance policy. */
export function resolveGovernedRecognitionAccreditorAnchor(input: {
  policy: GovernancePolicyRecord;
  activePolicyCommitment: string;
  scope: z.infer<typeof ScopeSchema>;
  evaluatedAtMs: number;
}): { anchor: RecognitionAccreditorAnchor; commitment: string } {
  const policy = GovernancePolicyRecordSchema.parse(input.policy);
  const activeCommitment = HashHexSchema.parse(input.activePolicyCommitment);
  const scope = ScopeSchema.parse(input.scope);
  if (!Number.isSafeInteger(input.evaluatedAtMs) || input.evaluatedAtMs < 0) {
    throw new Error("Recognition accreditation evaluation time is invalid");
  }
  if (policy.status !== "active" || policy.registryId !== scope.registryId
    || computeGovernancePolicySnapshotCommitment(deriveGovernancePolicySnapshot(policy)) !== activeCommitment) {
    throw new Error("Recognition accreditor policy is not the active governed policy");
  }
  const at = input.evaluatedAtMs;
  if (at < Date.parse(policy.effectiveFrom)
    || (policy.effectiveUntil !== undefined && at >= Date.parse(policy.effectiveUntil))) {
    throw new Error("Recognition accreditor policy is outside its effective window");
  }
  const anchor = policy.recognitionAccreditorAnchors.find((candidate) =>
    candidate.recognizedRegistryId === scope.recognizedRegistryId
    && candidate.scopeResourceType === scope.scopeResourceType
    && candidate.scopeResourceId === scope.scopeResourceId);
  if (anchor === undefined || at < Date.parse(anchor.effectiveFrom)
    || at >= Date.parse(anchor.effectiveUntil)) {
    throw new Error("No active governed recognition accreditor anchor matches the exact scope");
  }
  return { anchor, commitment: recognitionAccreditorAnchorCommitment(anchor) };
}
