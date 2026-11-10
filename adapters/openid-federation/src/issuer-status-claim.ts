import type { JWK } from "jose";

import {
  verifyDecisionEvidenceWithTrustedReaders,
  type DecisionEvidenceCandidate,
  type TrustedDecisionEvidenceReaders,
} from "@midnight-ntwrk/trust-registry-client";
import {
  DecisionEvidenceSchema,
  computeAuthorizationStatementLeafHash,
  type DecisionEvidenceSelection,
} from "@midnight-ntwrk/trust-registry-domain";

import { verifyEntityStatement } from "./statements.js";

export type FederatedIssuerStatusClaimInput = {
  jwt: string;
  jwks: { keys: JWK[] };
  /** This identity and its JWKS must be authenticated by the embedding federation consumer. */
  expectedPublisher: string;
  decisionEvidence: unknown;
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">;
  readers: TrustedDecisionEvidenceReaders;
};

/** A signed publisher statement is accepted only with matching independently verified current grant evidence. */
export const verifyFederatedIssuerStatusClaim = async (
  input: FederatedIssuerStatusClaimInput,
): Promise<Extract<DecisionEvidenceCandidate, { role: "issuer" }>> => {
  const statement = await verifyEntityStatement({ jwt: input.jwt, jwks: input.jwks });
  if (statement.iss !== input.expectedPublisher || statement.sub !== input.selection.subjectDid) {
    throw new Error("Federation issuer status claim publisher or subject mismatch");
  }
  const metadata = statement.metadata?.midnight_trust_registry;
  if (metadata?.statement_kind !== "authorization" || metadata.role !== "issuer") {
    throw new Error("Federation issuer status claim requires issuer authorization metadata");
  }
  const bundle = metadata.authorization_bundle;
  const evidence = DecisionEvidenceSchema.parse(input.decisionEvidence);
  if (bundle.authorization?.role !== "issuer" || evidence.role !== "issuer") {
    throw new Error("Federation issuer status claim requires issuer decision evidence");
  }
  if (
    metadata.registry_id !== input.selection.registryId ||
    bundle.subjectDid !== input.selection.subjectDid ||
    bundle.authorization.status !== "active" ||
    bundle.epoch.epochId !== evidence.epoch.epochId ||
    bundle.epoch.stateRoot !== evidence.epoch.stateRoot ||
    bundle.epoch.eventRoot !== evidence.epoch.eventRoot ||
    bundle.epoch.policyRoot !== evidence.epoch.policyRoot ||
    bundle.policy.policyId !== evidence.policy.policyId ||
    bundle.policy.version !== evidence.policy.policyVersion ||
    computeAuthorizationStatementLeafHash(bundle.authorization) !==
      computeAuthorizationStatementLeafHash(evidence.grant)
  ) {
    throw new Error("Federation issuer status claim does not match decision evidence");
  }

  const candidate = await verifyDecisionEvidenceWithTrustedReaders(
    evidence, input.selection, input.readers,
  );
  if (candidate.role !== "issuer" || candidate.grantStatus !== "active") {
    throw new Error("Federation issuer status claim lacks a current active issuer grant");
  }
  return candidate;
};
