import { Buffer } from "node:buffer";

import { pureCircuits } from "@midnight-ntwrk/credential-compact";
import type { MidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import type { TrustedDecisionEvidenceReaders } from "@midnight-ntwrk/trust-registry-client";
import type { DecisionEvidenceSelection } from "@midnight-ntwrk/trust-registry-domain";

import { createVcSignerCandidateFromTrustedDecision } from "./vc-signer-candidate.js";
import { pinnedVcAuthority, type PinnedVcAuthority, type VcAuthoritySigner } from "./vc-signer-authorization.js";

const sameBytes = (left: Uint8Array, right: Uint8Array): boolean => Buffer.from(left).equals(Buffer.from(right));

/** A signer-side gate: re-read finalized quorum and DID state before invoking key custody. */
export const createQuorumGatedVcAuthoritySigner = (input: {
  evidence: unknown;
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">;
  readers: TrustedDecisionEvidenceReaders;
  method: MidnightDIDMethodBinding;
  pinnedAnchor: PinnedVcAuthority;
  sign: VcAuthoritySigner;
}): VcAuthoritySigner => async (request) => {
  const { candidate, descriptor } = await createVcSignerCandidateFromTrustedDecision(
    input.evidence, input.selection, input.readers, input.method,
  );
  if (candidate.networkId !== input.pinnedAnchor.domain.networkId
    || candidate.registryId !== input.pinnedAnchor.domain.registryId
    || candidate.contractAddress !== input.pinnedAnchor.domain.registryContractAddress) {
    throw new Error("Authority signer registry domain does not match finalized decision");
  }
  const authority = pinnedVcAuthority(input.pinnedAnchor);
  if (!sameBytes(request.authority.domainCommitment, authority.domainCommitment)
    || !sameBytes(request.authority.verificationMethodRef.controllerAddress.bytes,
      authority.verificationMethodRef.controllerAddress.bytes)
    || !sameBytes(request.authority.verificationMethodRef.methodId, authority.verificationMethodRef.methodId)
    || request.authority.publicKey.x !== authority.publicKey.x
    || request.authority.publicKey.y !== authority.publicKey.y
    || request.decisionSequence !== descriptor.decisionSequence
    || !sameBytes(request.decisionRoot,
      pureCircuits.signerAuthorizationDecisionRoot(descriptor, authority.domainCommitment))) {
    throw new Error("Authority signer request does not match finalized descriptor");
  }
  const proof = await input.sign(request);
  pureCircuits.assertValidSignerAuthorizationProof(descriptor, proof, authority);
  return proof;
};
