import { Buffer } from "node:buffer";

import { decodeJubjubJwkCoordinate } from "@midnight-ntwrk/midnight-did-domain";
import {
  verifyDecisionEvidenceWithTrustedReaders,
  type TrustedDecisionEvidenceReaders,
} from "@midnight-ntwrk/trust-registry-client";
import type { AuthorizationScope, DecisionEvidenceSelection } from "@midnight-ntwrk/trust-registry-domain";

import type { ApplicationVpFamilyAdapter } from "./application-vp-verifier.js";

/** Selection and readers are host-owned; the presented credential supplies neither trust anchor. */
export function createGovernedApplicationIssuerEligibility(input: {
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">;
  readers: TrustedDecisionEvidenceReaders;
  loadEvidence: () => Promise<unknown>;
  allowedApplicationRoles: readonly AuthorizationScope["role"][];
}): ApplicationVpFamilyAdapter<unknown>["assertIssuerEligible"] {
  return async (material, applicationScope) => {
    if (input.selection.role !== "issuer"
      || !input.allowedApplicationRoles.includes(applicationScope.role)
      || material.issuerDid !== input.selection.subjectDid) {
      throw new Error("Credential issuer is not selected by application policy");
    }
    const candidate = await verifyDecisionEvidenceWithTrustedReaders(
      await input.loadEvidence(),
      input.selection,
      input.readers,
    );
    if (candidate.role !== "issuer"
      || candidate.grantStatus !== "active"
      || candidate.subjectDid !== material.issuerDid) {
      throw new Error("Credential issuer has no active governed grant");
    }
    const methodId = material.issuerMethodId.startsWith("#")
      ? `${material.issuerDid}${material.issuerMethodId}`
      : material.issuerMethodId;
    if (candidate.didMethod.methodId !== methodId
      || candidate.didMethod.relationship !== "assertionMethod"
      || decodeJubjubJwkCoordinate(candidate.didMethod.publicKeyJwk.x) !== material.credentialProof.publicKey.x
      || decodeJubjubJwkCoordinate(candidate.didMethod.publicKeyJwk.y) !== material.credentialProof.publicKey.y
      || candidate.statusPolicyBinding.statusRegistryId
        !== `0x${Buffer.from(material.statusBinding.registryRef.registryId).toString("hex")}`) {
      throw new Error("Credential issuer key or status registry differs from the governed grant");
    }
    return candidate.statusPolicyBinding;
  };
}
