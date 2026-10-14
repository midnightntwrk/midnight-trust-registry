import { describe, expect, it } from "vitest";

import {
  computeCreateVcAuthorityKeyPayloadHash,
  deriveJubjubPublicKeyFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";

import { bytes32Commitment, createMidnightDid } from "../fixtures.js";
import { prepareVcAuthorityKeyRegistration } from "../vc-authority-registration.js";
import { vcAuthorityDomainCommitment, vcAuthorityDomainFields } from "../vc-signer-authorization.js";

const registryId = "registry:vc-authority-registration:trusted";
const registryContractAddress = `0x${"a".repeat(64)}`;
const authorityDid = createMidnightDid("vc-authority-registration");
const domain = {
  networkId: "undeployed",
  consumerContractAddress: `0x${"b".repeat(64)}`,
  registryId,
  registryContractAddress,
  authorityDid,
  authorityMethodId: `${authorityDid}#authority-1`,
};
const input = {
  domain,
  registryId,
  registryContractAddress,
  keyIdCommitment: bytes32Commitment("vc-authority:registration-key"),
  publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(47)),
  policyCommitment: bytes32Commitment("vc-authority:registration-policy"),
  policyVersion: 2n,
};

describe("VC authority key registration preparation", () => {
  it("binds canonical domain preimages to the exact Compact governance payload", () => {
    const prepared = prepareVcAuthorityKeyRegistration(input);
    const fields = vcAuthorityDomainFields(domain);
    expect(prepared.authorityDidCommitment).toEqual(fields.authorityDidCommitment);
    expect(prepared.authorityMethodIdCommitment).toEqual(fields.authorityMethodIdCommitment);
    expect(prepared.networkIdCommitment).toEqual(fields.networkIdCommitment);
    expect(prepared.consumerContractAddress).toEqual(fields.consumerContractAddress);
    expect(prepared.domainCommitment).toEqual(vcAuthorityDomainCommitment(domain));
    expect(prepared.payloadHash).toEqual(computeCreateVcAuthorityKeyPayloadHash(
      input.keyIdCommitment,
      fields.authorityDidCommitment,
      fields.authorityMethodIdCommitment,
      input.publicKey,
      fields.networkIdCommitment,
      fields.consumerContractAddress,
      prepared.domainCommitment,
      input.policyCommitment,
      input.policyVersion,
    ));
  });

  it("rejects mismatched registries and malformed authority domain preimages", () => {
    expect(() => prepareVcAuthorityKeyRegistration({
      ...input, domain: { ...domain, registryId: "registry:other:trusted" },
    })).toThrow(/target registry/u);
    expect(() => prepareVcAuthorityKeyRegistration({
      ...input, domain: { ...domain, registryContractAddress: `0x${"c".repeat(64)}` },
    })).toThrow(/target registry/u);
    expect(() => prepareVcAuthorityKeyRegistration({
      ...input, domain: { ...domain, networkId: "other" },
    })).toThrow(/network mismatch/u);
    expect(() => prepareVcAuthorityKeyRegistration({
      ...input, domain: { ...domain, authorityMethodId: `${authorityDid}#other#method` },
    })).toThrow(/absolute DID fragment/u);
    expect(() => prepareVcAuthorityKeyRegistration({
      ...input, domain: { ...domain, consumerContractAddress: "0xabc" },
    })).toThrow(/canonical 32-byte/u);
    expect(() => prepareVcAuthorityKeyRegistration({
      ...input, policyVersion: 0n,
    })).toThrow(/positive/u);
    expect(() => prepareVcAuthorityKeyRegistration({
      ...input, keyIdCommitment: new Uint8Array(31),
    })).toThrow(/32 bytes/u);
  });

  it("does not retain mutable caller-owned key and commitment values", () => {
    const publicKey = { ...input.publicKey };
    const keyIdCommitment = Uint8Array.from(input.keyIdCommitment);
    const prepared = prepareVcAuthorityKeyRegistration({ ...input, publicKey, keyIdCommitment });
    publicKey.x += 1n;
    keyIdCommitment[0] = keyIdCommitment[0]! ^ 1;
    expect(prepared.publicKey).toEqual(input.publicKey);
    expect(prepared.keyIdCommitment).toEqual(Uint8Array.from(input.keyIdCommitment));
  });
});
