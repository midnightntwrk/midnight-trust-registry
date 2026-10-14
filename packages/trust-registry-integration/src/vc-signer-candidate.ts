import { Buffer } from "node:buffer";

import { AuthorizationState, SignerRole, VerificationRelationship, pureCircuits } from "@midnight-ntwrk/credential-compact";
import {
  createMidnightDIDSignerDescriptor,
  midnightDIDMethodId,
  type MidnightDIDMethodBinding,
} from "@midnight-ntwrk/credential-did-midnight";
import { decodeJubjubJwkCoordinate, parseMidnightDID, parseMidnightDIDString } from "@midnight-ntwrk/midnight-did-domain";
import {
  verifyDecisionEvidenceWithTrustedReaders,
  type TrustedDecisionEvidenceReaders,
} from "@midnight-ntwrk/trust-registry-client";
import {
  sha256Hex,
  type DecisionEvidenceSelection,
} from "@midnight-ntwrk/trust-registry-domain";
import { vcScopeCommitmentFromRegistryScope } from "./vc-scope.js";

const bytes32FromHex = (value: string, label: string): Uint8Array => {
  if (!/^0x[0-9a-f]{64}$/u.test(value)) throw new Error(`${label} must be a canonical 32-byte hash`);
  return Buffer.from(value.slice(2), "hex");
};

/**
 * Constructs a VC descriptor candidate, not a signer-authorization proof.
 * Readers and DID resolver must be independently trusted by the caller.
 */
export const createVcSignerCandidateFromTrustedDecision = async (
  evidence: unknown,
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">,
  readers: TrustedDecisionEvidenceReaders,
  method: MidnightDIDMethodBinding,
) => {
  const candidate = await verifyDecisionEvidenceWithTrustedReaders(evidence, selection, readers);
  const vcScopeCommitment = vcScopeCommitmentFromRegistryScope(candidate.scope);
  const didId = parseMidnightDID(parseMidnightDIDString(candidate.subjectDid)).id;
  const fragment = candidate.didMethod.methodId.slice(candidate.subjectDid.length);
  if (!/^#[^#]+$/u.test(fragment)
    || candidate.didMethod.methodId !== `${candidate.subjectDid}${fragment}`
    || Buffer.from(method.verificationMethodRef.controllerAddress.bytes).toString("hex") !== didId
    || !Buffer.from(method.verificationMethodRef.methodId).equals(Buffer.from(midnightDIDMethodId(fragment)))) {
    throw new Error("VC method binding does not match the trusted DID method");
  }
  const key = candidate.didMethod.publicKeyJwk;
  if (
    method.publicKey.x !== decodeJubjubJwkCoordinate(key.x, "Jubjub x")
    || method.publicKey.y !== decodeJubjubJwkCoordinate(key.y, "Jubjub y")
    || method.didStateVersion !== BigInt(candidate.didStateVersion)
    || method.verificationRelationship !== VerificationRelationship[candidate.didMethod.relationship]
  ) {
    throw new Error("VC method key, relationship, or DID state version does not match trusted evidence");
  }
  const descriptor = createMidnightDIDSignerDescriptor(method, {
    authorizationId: bytes32FromHex(sha256Hex(candidate.authorizationId), "authorizationId"),
    decisionSequence: BigInt(candidate.decisionSequence),
    state: AuthorizationState.active,
    role: candidate.role === "issuer" ? SignerRole.issuer : SignerRole.verifier,
    scopeCommitment: vcScopeCommitment,
    policyCommitment: bytes32FromHex(candidate.policyRoot, "policyRoot"),
  });
  pureCircuits.assertValidAuthorizedSignerDescriptor(descriptor);
  return { candidate, descriptor };
};
