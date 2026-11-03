import {
  computeCreateVcAuthorityKeyPayloadHash,
  deriveJubjubPublicKeyFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";

import {
  vcAuthorityDomainCommitment,
  vcAuthorityDomainFields,
  type VcAuthorityDomain,
} from "./vc-signer-authorization.js";

/** Prepare the exact preimage and payload that a governance quorum must sign. */
export const prepareVcAuthorityKeyRegistration = (input: {
  domain: VcAuthorityDomain;
  registryId: string;
  registryContractAddress: string;
  keyIdCommitment: Uint8Array;
  publicKey: ReturnType<typeof deriveJubjubPublicKeyFromSeed>;
  policyCommitment: Uint8Array;
  policyVersion: bigint;
}) => {
  if (input.domain.registryId !== input.registryId
    || input.domain.registryContractAddress !== input.registryContractAddress) {
    throw new Error("VC authority domain does not match the target registry");
  }
  if (input.keyIdCommitment.length !== 32 || input.policyCommitment.length !== 32) {
    throw new Error("VC authority key and policy commitments must be 32 bytes");
  }
  if (input.policyVersion < 1n) {
    throw new Error("VC authority policy version must be positive");
  }
  const fields = vcAuthorityDomainFields(input.domain);
  const domainCommitment = vcAuthorityDomainCommitment(input.domain);
  const payloadHash = computeCreateVcAuthorityKeyPayloadHash(
    input.keyIdCommitment,
    fields.authorityDidCommitment,
    fields.authorityMethodIdCommitment,
    input.publicKey,
    fields.networkIdCommitment,
    fields.consumerContractAddress,
    domainCommitment,
    input.policyCommitment,
    input.policyVersion,
  );
  return {
    keyIdCommitment: Uint8Array.from(input.keyIdCommitment),
    authorityDidCommitment: fields.authorityDidCommitment,
    authorityMethodIdCommitment: fields.authorityMethodIdCommitment,
    publicKey: { ...input.publicKey },
    networkIdCommitment: fields.networkIdCommitment,
    consumerContractAddress: fields.consumerContractAddress,
    domainCommitment,
    policyCommitment: Uint8Array.from(input.policyCommitment),
    policyVersion: input.policyVersion,
    payloadHash: Uint8Array.from(payloadHash),
  };
};
