import type { DecisionEvidenceSelection, DecisionEvidence } from "@midnight-ntwrk/trust-registry-domain";

import { buildDecisionEvidenceClaim, type DecisionEvidenceBuildInput } from "./decision-evidence-builder.js";
import { verifyDecisionEvidenceWithTrustedReaders, type TrustedDecisionEvidenceReaders } from "./decision-context.js";

type Role = "issuer" | "verifier";
type Selection = Omit<DecisionEvidenceSelection, "evaluationTime">;

export type DecisionEvidenceSourceCandidate = {
  buildInput: DecisionEvidenceBuildInput;
  selection: Selection;
};

/** The indexed bundle is untrusted; reader selection and finality must come from an independent host port. */
export function createVerifiedDecisionEvidenceSource(input: {
  loadCandidate(role: Role, authorizationId: string): Promise<DecisionEvidenceSourceCandidate | null>;
  readersFor(role: Role, authorizationId: string, selection: Selection): Promise<TrustedDecisionEvidenceReaders | null>;
}): (role: Role, authorizationId: string) => Promise<DecisionEvidence | null> {
  return async (role, authorizationId) => {
    if ((role !== "issuer" && role !== "verifier")
      || authorizationId.length === 0 || authorizationId.length > 256) {
      throw new Error("Invalid decision-evidence source lookup");
    }
    const candidate = await input.loadCandidate(role, authorizationId);
    if (candidate === null) return null;
    const evidence = buildDecisionEvidenceClaim(candidate.buildInput);
    if (evidence.role !== role || evidence.grant.authorizationId !== authorizationId
      || candidate.selection.role !== role) {
      throw new Error("Decision-evidence source returned a different grant or role");
    }
    const readers = await input.readersFor(role, authorizationId, candidate.selection);
    if (readers === null) throw new Error("Finalized decision readers are unavailable");
    await verifyDecisionEvidenceWithTrustedReaders(evidence, candidate.selection, readers);
    return evidence;
  };
}
