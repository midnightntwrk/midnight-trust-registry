import { parseMidnightDIDDocument } from "@midnight-ntwrk/midnight-did";
import type { DecisionEvidence } from "@midnight-ntwrk/trust-registry-domain";

export type DidStateObservation = {
  networkId: string;
  blockHash: string;
  stateVersion: string;
  didDocument: unknown;
};

/** The caller must authenticate the observation's block, version, and finality. */
export const assertDecisionEvidenceDidMethodMatchesObservation = (
  claim: DecisionEvidence["didMethod"],
  observation: DidStateObservation,
  expectedNetworkId: string,
): void => {
  if (
    observation.networkId !== expectedNetworkId
    || observation.blockHash !== claim.stateEvidence.blockHash
    || observation.stateVersion !== claim.stateVersion
  ) {
    throw new Error("Decision evidence DID state anchor mismatch");
  }
  const document = parseMidnightDIDDocument(observation.didDocument);
  if (
    document.id !== claim.did
    || !claim.did.startsWith(`did:midnight:${expectedNetworkId}:`)
    || claim.controller !== claim.did
  ) {
    throw new Error("Decision evidence DID subject or controller mismatch");
  }
  const methods = document.verificationMethod?.filter((method) => method.id === claim.methodId) ?? [];
  if (methods.length !== 1) {
    throw new Error("Decision evidence DID method is absent or ambiguous");
  }
  const method = methods[0]!;
  if (
    method.type !== "JsonWebKey"
    || method.controller !== claim.controller
    || method.publicKeyJwk.kty !== claim.publicKeyJwk.kty
    || method.publicKeyJwk.crv !== claim.publicKeyJwk.crv
    || method.publicKeyJwk.x !== claim.publicKeyJwk.x
    || method.publicKeyJwk.y !== claim.publicKeyJwk.y
  ) {
    throw new Error("Decision evidence DID method or key mismatch");
  }
  if (!document[claim.relationship]?.some((id) => id === claim.methodId)) {
    throw new Error("Decision evidence DID relationship is absent");
  }
};
