import type { DecisionEvidenceSelection, DecisionEvidence } from "@midnight-ntwrk/trust-registry-domain";

import { buildDecisionEvidenceClaim, type DecisionEvidenceBuildInput } from "./decision-evidence-builder.js";
import { verifyDecisionEvidenceWithTrustedReaders, type TrustedDecisionEvidenceReaders } from "./decision-context.js";

type Role = "issuer" | "verifier";
type Selection = Omit<DecisionEvidenceSelection, "evaluationTime">;

export type DecisionEvidenceSourceCandidate = { buildInput: DecisionEvidenceBuildInput };

export type TrustedDecisionEvidenceSourceContext = {
  selection: Selection;
  readers: TrustedDecisionEvidenceReaders;
};

/** The indexed bundle is untrusted; selection, reader choice, and finality belong to the independent host port. */
export function createVerifiedDecisionEvidenceSource(input: {
  loadCandidate(role: Role, authorizationId: string): Promise<DecisionEvidenceSourceCandidate | null>;
  trustedContextFor(role: Role, authorizationId: string): Promise<TrustedDecisionEvidenceSourceContext | null>;
}): (role: Role, authorizationId: string) => Promise<DecisionEvidence | null> {
  return async (role, authorizationId) => {
    if ((role !== "issuer" && role !== "verifier")
      || authorizationId.length === 0 || authorizationId.length > 256) {
      throw new Error("Invalid decision-evidence source lookup");
    }
    const candidate = await input.loadCandidate(role, authorizationId);
    if (candidate === null) return null;
    const evidence = buildDecisionEvidenceClaim(candidate.buildInput);
    if (evidence.role !== role || evidence.grant.authorizationId !== authorizationId) {
      throw new Error("Decision-evidence source returned a different grant or role");
    }
    const context = await input.trustedContextFor(role, authorizationId);
    if (context === null) throw new Error("Finalized decision context is unavailable");
    if (context.selection.role !== role) throw new Error("Trusted decision selection has a different role");
    await verifyDecisionEvidenceWithTrustedReaders(evidence, context.selection, context.readers);
    return evidence;
  };
}
