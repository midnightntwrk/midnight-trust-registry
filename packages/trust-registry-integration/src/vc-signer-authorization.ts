import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import {
  pureCircuits,
  type Proof,
  type SignerAuthorizationAuthority,
  type AuthorizedSignerDescriptor,
} from "@midnight-ntwrk/credential-compact";
import { midnightDIDMethodId, type MidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDID, parseMidnightDIDString } from "@midnight-ntwrk/midnight-did-domain";
import type { TrustedDecisionEvidenceReaders } from "@midnight-ntwrk/trust-registry-client";
import type { DecisionEvidenceSelection } from "@midnight-ntwrk/trust-registry-domain";

import { createVcSignerCandidateFromTrustedDecision, type ScopeMapping } from "./vc-signer-candidate.js";

export type VcAuthorityDomain = {
  networkId: string;
  consumerContractAddress: string;
  registryId: string;
  registryContractAddress: string;
  authorityDid: string;
  authorityMethodId: string;
};

export type PinnedVcAuthority = {
  domain: VcAuthorityDomain;
  publicKey: SignerAuthorizationAuthority["publicKey"];
};

export type VcAuthoritySigner = (request: {
  decisionRoot: Uint8Array;
  decisionSequence: bigint;
  authority: SignerAuthorizationAuthority;
}) => Promise<Proof>;

/** Versioned, length-prefixed UTF-8 tuple; consumers pin every preimage field. */
export const vcAuthorityDomainCommitment = (domain: VcAuthorityDomain): Uint8Array => {
  const values = [
    domain.networkId,
    domain.consumerContractAddress,
    domain.registryId,
    domain.registryContractAddress,
    domain.authorityDid,
    domain.authorityMethodId,
  ];
  if (values.some((value) => typeof value !== "string" || value.length === 0)) {
    throw new Error("VC authority domain fields must be nonempty strings");
  }
  if (!/^0x[0-9a-f]{64}$/u.test(domain.consumerContractAddress)
    || !/^0x[0-9a-f]{64}$/u.test(domain.registryContractAddress)) {
    throw new Error("VC authority contract addresses must be canonical 32-byte hashes");
  }
  const canonicalDid = parseMidnightDIDString(domain.authorityDid);
  if (canonicalDid !== domain.authorityDid) throw new Error("VC authority DID must be canonical");
  const did = parseMidnightDID(canonicalDid);
  if (did.network.toLowerCase() !== domain.networkId) throw new Error("VC authority DID network mismatch");
  const fragment = domain.authorityMethodId.slice(domain.authorityDid.length);
  if (!/^#[^#]+$/u.test(fragment) || domain.authorityMethodId !== `${domain.authorityDid}${fragment}`) {
    throw new Error("VC authority method must be an absolute DID fragment");
  }
  const hash = createHash("sha256").update("tr:vc-authority-domain:v1\0", "utf8");
  for (const value of values) {
    const encoded = Buffer.from(value, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(encoded.length);
    hash.update(length).update(encoded);
  }
  return hash.digest();
};

export const pinnedVcAuthority = (anchor: PinnedVcAuthority): SignerAuthorizationAuthority => {
  const did = parseMidnightDID(parseMidnightDIDString(anchor.domain.authorityDid));
  const fragment = anchor.domain.authorityMethodId.slice(anchor.domain.authorityDid.length);
  const authority = {
    domainCommitment: vcAuthorityDomainCommitment(anchor.domain),
    verificationMethodRef: {
      controllerAddress: { bytes: Buffer.from(did.id, "hex") },
      methodId: midnightDIDMethodId(fragment),
    },
    publicKey: anchor.publicKey,
  };
  pureCircuits.assertValidSignerAuthorizationAuthority(authority);
  return authority;
};

/** The signer port must independently authorize the request; this layer checks its proof before publication. */
export const issueVcSignerAuthorizationFromTrustedDecision = async (input: {
  evidence: unknown;
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">;
  readers: TrustedDecisionEvidenceReaders;
  method: MidnightDIDMethodBinding;
  scopeMapping: ScopeMapping;
  anchor: PinnedVcAuthority;
  signer: VcAuthoritySigner;
}): Promise<{ descriptor: AuthorizedSignerDescriptor; proof: Proof }> => {
  const { candidate, descriptor } = await createVcSignerCandidateFromTrustedDecision(
    input.evidence, input.selection, input.readers, input.method, input.scopeMapping,
  );
  if (
    input.anchor.domain.networkId !== candidate.networkId
    || input.anchor.domain.registryId !== candidate.registryId
    || input.anchor.domain.registryContractAddress !== candidate.contractAddress
  ) {
    throw new Error("VC authority domain does not bind the trusted registry decision");
  }
  const authority = pinnedVcAuthority(input.anchor);
  const proof = await input.signer({
    decisionRoot: pureCircuits.signerAuthorizationDecisionRoot(descriptor, authority.domainCommitment),
    decisionSequence: descriptor.decisionSequence,
    authority,
  });
  pureCircuits.assertValidSignerAuthorizationProof(descriptor, proof, authority);
  return { descriptor, proof };
};

/** The consumer must supply an authenticated previous state (or explicit null on first install). */
export const verifyVcSignerAuthorizationForConsumer = (
  descriptor: AuthorizedSignerDescriptor,
  proof: Proof,
  pinnedAnchor: PinnedVcAuthority,
  previous: AuthorizedSignerDescriptor | null,
): void => {
  pureCircuits.assertValidSignerAuthorizationProof(descriptor, proof, pinnedVcAuthority(pinnedAnchor));
  if (previous !== null) pureCircuits.assertValidSignerAuthorizationUpdate(previous, descriptor);
};
