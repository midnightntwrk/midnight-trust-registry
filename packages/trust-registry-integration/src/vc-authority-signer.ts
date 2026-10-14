import { Buffer } from "node:buffer";

import { pureCircuits } from "@midnight-ntwrk/credential-compact";
import type { MidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDDocument } from "@midnight-ntwrk/midnight-did";
import { encodeJubjubJwkCoordinate } from "@midnight-ntwrk/midnight-did-domain";
import type { DidStateObservation, TrustedDecisionEvidenceReaders } from "@midnight-ntwrk/trust-registry-client";
import {
  VcAuthorityKeyStatus,
  type VcAuthorityKeyRecord,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import type { DecisionEvidenceSelection } from "@midnight-ntwrk/trust-registry-domain";

import { createInactiveVcSignerCandidateFromTrustedDecision, createVcSignerCandidateFromTrustedDecision } from "./vc-signer-candidate.js";
import {
  pinnedVcAuthority,
  vcAuthorityDomainFields,
  type PinnedVcAuthority,
  type VcAuthorityDomain,
  type VcAuthoritySigner,
} from "./vc-signer-authorization.js";

const sameBytes = (left: Uint8Array, right: Uint8Array): boolean => Buffer.from(left).equals(Buffer.from(right));

const assertCurrentAuthorityMethod = (
  observation: DidStateObservation | null,
  anchor: PinnedVcAuthority,
): void => {
  if (observation === null
    || observation.networkId !== anchor.domain.networkId
    || observation.deactivated
    || observation.blockHash.length === 0
    || observation.stateVersion.length === 0) {
    throw new Error("Current finalized VC authority DID state is unavailable");
  }
  let document: ReturnType<typeof parseMidnightDIDDocument>;
  try {
    document = parseMidnightDIDDocument(observation.didDocument);
  } catch (cause) {
    throw new Error("Current finalized VC authority DID method is invalid", { cause });
  }
  const did = anchor.domain.authorityDid;
  const methodId = anchor.domain.authorityMethodId;
  const absolute = (reference: string): string => reference.startsWith("#") ? `${did}${reference}` : reference;
  const methods = document.verificationMethod?.filter((method) => absolute(method.id) === methodId) ?? [];
  const method = methods[0];
  if (document.id !== did
    || methods.length !== 1
    || method?.type !== "JsonWebKey"
    || method.controller !== did
    || method.publicKeyJwk.kty !== "EC"
    || method.publicKeyJwk.crv !== "Jubjub"
    || method.publicKeyJwk.x !== encodeJubjubJwkCoordinate(anchor.publicKey.x)
    || method.publicKeyJwk.y !== encodeJubjubJwkCoordinate(anchor.publicKey.y)
    || !document.assertionMethod?.some((reference) => absolute(reference) === methodId)) {
    throw new Error("Current finalized VC authority DID method does not authorize this key");
  }
};

export type FinalizedVcAuthorityState = {
  registryIdCommitment: Uint8Array;
  currentPolicyCommitment: Uint8Array;
  currentPolicyVersion: bigint;
  currentKey: VcAuthorityKeyRecord | null;
};

/** Return one authenticated ledger snapshot from the exact finalized registry contract. */
export type TrustedVcAuthorityKeyReader = {
  readCurrentFinalizedVcAuthorityState(domain: VcAuthorityDomain): Promise<FinalizedVcAuthorityState | null>;
};

/** A signer-side gate: re-read finalized quorum and DID state before invoking key custody. */
export const createQuorumGatedVcAuthoritySigner = (input: {
  evidence: unknown;
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">;
  readers: TrustedDecisionEvidenceReaders;
  method: MidnightDIDMethodBinding;
  pinnedAnchor: PinnedVcAuthority;
  authorityKeyIdCommitment: Uint8Array;
  authorityKeyReader: TrustedVcAuthorityKeyReader;
  sign: VcAuthoritySigner;
  inactiveState?: "suspended" | "revoked";
}): VcAuthoritySigner => async (request) => {
  const { candidate, descriptor } = input.inactiveState === undefined
    ? await createVcSignerCandidateFromTrustedDecision(
      input.evidence, input.selection, input.readers, input.method,
    )
    : await createInactiveVcSignerCandidateFromTrustedDecision(
      input.evidence, input.selection, input.readers, input.method, input.inactiveState,
    );
  if (candidate.networkId !== input.pinnedAnchor.domain.networkId
    || candidate.registryId !== input.pinnedAnchor.domain.registryId
    || candidate.contractAddress !== input.pinnedAnchor.domain.registryContractAddress) {
    throw new Error("Authority signer registry domain does not match finalized decision");
  }
  const authority = pinnedVcAuthority(input.pinnedAnchor);
  const fields = vcAuthorityDomainFields(input.pinnedAnchor.domain);
  const state = await input.authorityKeyReader.readCurrentFinalizedVcAuthorityState(
    input.pinnedAnchor.domain,
  );
  const governedKey = state?.currentKey ?? null;
  if (input.authorityKeyIdCommitment.length !== 32
    || state === null
    || !sameBytes(state.registryIdCommitment, fields.registryIdCommitment)
    || !sameBytes(state.currentPolicyCommitment, descriptor.policyCommitment)
    || state.currentPolicyVersion < 1n
    || governedKey === null
    || governedKey.status !== VcAuthorityKeyStatus.active
    || !sameBytes(governedKey.keyIdCommitment, input.authorityKeyIdCommitment)
    || !sameBytes(governedKey.authorityDidCommitment, fields.authorityDidCommitment)
    || !sameBytes(governedKey.authorityMethodIdCommitment, fields.authorityMethodIdCommitment)
    || !sameBytes(governedKey.networkIdCommitment, fields.networkIdCommitment)
    || !sameBytes(governedKey.consumerContractAddress, fields.consumerContractAddress)
    || !sameBytes(governedKey.domainCommitment, authority.domainCommitment)
    || !sameBytes(governedKey.policyCommitment, descriptor.policyCommitment)
    || governedKey.policyVersion !== state.currentPolicyVersion
    || governedKey.publicKey.x !== authority.publicKey.x
    || governedKey.publicKey.y !== authority.publicKey.y
    || governedKey.registeredAtSequence > descriptor.decisionSequence
    || governedKey.lastStatusSequence > descriptor.decisionSequence) {
    throw new Error("Current finalized VC authority key does not authorize this signature");
  }
  assertCurrentAuthorityMethod(
    await input.readers.readCurrentFinalizedDidState(
      input.pinnedAnchor.domain.authorityDid,
      input.pinnedAnchor.domain.networkId,
      descriptor.decisionSequence.toString(),
    ),
    input.pinnedAnchor,
  );
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
