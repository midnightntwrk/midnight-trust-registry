import { Buffer } from "node:buffer";

import type { TrustRegistrySimulator } from "@midnight-ntwrk/trust-registry-contract/testing";
import {
  computeAuditorEvidenceBoundProposalPayloadHash,
  computeCreateAuditorAuthorizationPayloadHash,
  computeCreateIssuerAuthorizationPayloadHash,
  computeCreateMaintainerMembershipPayloadHash,
  computeCreateRecognitionPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeIssuerEvidenceBoundProposalPayloadHash,
  computeMaintainerEvidenceBoundProposalPayloadHash,
  computeRecognitionEvidenceBoundProposalPayloadHash,
  computeVerifierEvidenceBoundProposalPayloadHash,
  verifyAuditorProposalEvidenceSignature,
  verifyIssuerProposalEvidenceSignature,
  verifyMaintainerProposalEvidenceSignature,
  verifyRecognitionProposalEvidenceSignature,
  verifyVerifierProposalEvidenceSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

import {
  GovernedProposalObservationSchema,
  type GovernedProposalObservation,
} from "./governed-proposal-observation.js";

type Ledger = ReturnType<TrustRegistrySimulator["getLedger"]>;
export type ProposalRole = "issuer" | "verifier" | "auditor" | "maintainer" | "recognition";

/** The caller must supply an independently finalized ledger view, not an unconfirmed transaction result. */
export type FinalizedProposalLedgerReader = () => Promise<Ledger>;

export type CompactProposalEvidenceSnapshot = GovernedProposalObservation & {
  role: ProposalRole;
  authorizationId: string;
  verifierAuthorizationId: string;
  verifierDidCommitment: string;
  verifierKeyIdCommitment: string;
  verifierSuite: string;
  policyCommitment: string;
  policyVersion: string;
  verifierPublicKey: { x: string; y: string };
  verifierSignature: { announcement: { x: string; y: string }; response: string };
  subjectDidCommitment: string;
  grantPolicyIdCommitment: string;
  proposedAtSequence: string;
  boundActionPayloadHash: string;
  signatureVerified: true;
};

const hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new Error("Malformed Compact proposal evidence record");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export async function resolveCompactProposalObservation(
  readFinalizedLedger: FinalizedProposalLedgerReader,
  expectedRegistryId: string,
  role: ProposalRole,
  authorizationId: string,
): Promise<GovernedProposalObservation | null> {
  if (expectedRegistryId.length === 0 || expectedRegistryId.length > 256
    || authorizationId.length === 0 || authorizationId.length > 256) {
    throw new RangeError("Invalid proposal authorization ID");
  }
  if (!["issuer", "verifier", "auditor", "maintainer", "recognition"].includes(role)) {
    throw new RangeError("Invalid proposal role");
  }
  const key = Buffer.from(sha256Hex(authorizationId).slice(2), "hex");
  const ledger = await readFinalizedLedger();
  if (hex(ledger.registryId) !== sha256Hex(expectedRegistryId)) {
    throw new Error("Finalized ledger belongs to a different trust registry");
  }
  const records = role === "issuer" ? ledger.issuerProposalEvidenceRecords
    : role === "verifier" ? ledger.verifierProposalEvidenceRecords
      : role === "auditor" ? ledger.auditorProposalEvidenceRecords
        : role === "maintainer" ? ledger.maintainerProposalEvidenceRecords
          : ledger.recognitionProposalEvidenceRecords;
  if (!records.member(key)) return null;
  const record = records.lookup(key);
  return GovernedProposalObservationSchema.parse({
    eventHash: hex(record.proposalGovernanceEventHash),
    evidenceCommitment: hex(record.evidenceCommitment),
  });
}

/** A finalized-ledger projection, not a standalone finality or inclusion proof. */
export async function resolveCompactProposalEvidenceSnapshot(
  readFinalizedLedger: FinalizedProposalLedgerReader,
  expectedRegistryId: string,
  role: ProposalRole,
  authorizationId: string,
): Promise<CompactProposalEvidenceSnapshot | null> {
  if (expectedRegistryId.length === 0 || expectedRegistryId.length > 256
    || authorizationId.length === 0 || authorizationId.length > 256) {
    throw new RangeError("Invalid proposal authorization ID");
  }
  if (!["issuer", "verifier", "auditor", "maintainer", "recognition"].includes(role)) {
    throw new RangeError("Invalid proposal role");
  }
  const ledger = await readFinalizedLedger();
  if (hex(ledger.registryId) !== sha256Hex(expectedRegistryId)) {
    throw new Error("Finalized ledger belongs to a different trust registry");
  }
  const id = Buffer.from(sha256Hex(authorizationId).slice(2), "hex");
  const records = role === "issuer" ? ledger.issuerProposalEvidenceRecords
    : role === "verifier" ? ledger.verifierProposalEvidenceRecords
      : role === "auditor" ? ledger.auditorProposalEvidenceRecords
        : role === "maintainer" ? ledger.maintainerProposalEvidenceRecords
          : ledger.recognitionProposalEvidenceRecords;
  if (!records.member(id)) return null;
  const proposal = records.lookup(id);
  const authorizationRecords = role === "issuer" ? ledger.issuerAuthorizationRecords
    : role === "verifier" ? ledger.verifierAuthorizationRecords
      : role === "auditor" ? ledger.auditorAuthorizationRecords
        : role === "maintainer" ? ledger.maintainerMembershipRecords
          : ledger.recognitionRecords;
  if (!authorizationRecords.member(id)) {
    throw new Error("Proposal authorization is absent from the finalized ledger");
  }
  const authorization = authorizationRecords.lookup(id);
  const recordedId = "maintainerId" in authorization ? authorization.maintainerId
    : "recognitionId" in authorization ? authorization.recognitionId : authorization.authorizationId;
  const subjectDidCommitment = "maintainerDidCommitment" in authorization
    ? authorization.maintainerDidCommitment
    : "recognizedAuthorityDidCommitment" in authorization
      ? authorization.recognizedAuthorityDidCommitment : authorization.subjectDidCommitment;
  if (hex(recordedId) !== hex(id) || hex(authorization.evidenceHash) !== hex(proposal.evidenceCommitment)) {
    throw new Error("Proposal evidence does not match its authorization record");
  }
  if (!ledger.evidenceVerifierKeyAuthorizationIds.member(proposal.evidenceVerifierAuthorizationId)) {
    throw new Error("Proposal evidence verifier key is absent from the finalized ledger");
  }
  const key = ledger.evidenceVerifierKeyRecords.lookup(proposal.evidenceVerifierAuthorizationId);
  if (hex(key.authorizationId) !== hex(proposal.evidenceVerifierAuthorizationId)
    || hex(key.verifierDidCommitment) !== hex(proposal.evidenceVerifierDidCommitment)
    || hex(key.keyIdCommitment) !== hex(proposal.evidenceVerifierKeyIdCommitment)
    || hex(key.suite) !== hex(proposal.evidenceVerifierSuite)
    || hex(key.policyCommitment) !== hex(proposal.activePolicyCommitment)
    || key.policyVersion !== proposal.activePolicyVersion) {
    throw new Error("Proposal evidence verifier key does not match its ledger snapshot");
  }
  let basePayloadHash: Uint8Array;
  if (role === "issuer") {
    const record = ledger.issuerAuthorizationRecords.lookup(id);
    basePayloadHash = computeCreateIssuerAuthorizationPayloadHash(record.authorizationId, record.subjectDidCommitment,
      record.resourceType, record.resourceId, record.policyId, record.statusPolicyBindingCommitment,
      record.trustLevel, record.evidenceHash);
  } else if (role === "verifier") {
    const record = ledger.verifierAuthorizationRecords.lookup(id);
    basePayloadHash = computeCreateVerifierAuthorizationPayloadHash(record.authorizationId, record.subjectDidCommitment,
      record.requestResourceId, record.allowedAttributeSetCommitment, record.allowedPredicateSetCommitment,
      record.disclosureLevelCommitment, record.policyId, record.trustLevel, record.evidenceHash);
  } else if (role === "auditor") {
    const record = ledger.auditorAuthorizationRecords.lookup(id);
    basePayloadHash = computeCreateAuditorAuthorizationPayloadHash(record.authorizationId, record.subjectDidCommitment,
      record.requestResourceId, record.allowedAttributeSetCommitment, record.allowedPredicateSetCommitment,
      record.disclosureLevelCommitment, record.policyId, record.trustLevel, record.evidenceHash);
  } else if (role === "maintainer") {
    const record = ledger.maintainerMembershipRecords.lookup(id);
    basePayloadHash = computeCreateMaintainerMembershipPayloadHash(record.maintainerId, record.maintainerDidCommitment,
      record.keyId, record.publicKey, record.policyId, record.trustLevel, record.evidenceHash);
  } else {
    const record = ledger.recognitionRecords.lookup(id);
    basePayloadHash = computeCreateRecognitionPayloadHash(record.recognitionId, record.recognizedAuthorityDidCommitment,
      record.recognizedRegistryId, record.scopeResourceType, record.scopeResourceId, record.policyId,
      record.trustLevel, record.evidenceHash);
  }
  const bind = role === "issuer" ? computeIssuerEvidenceBoundProposalPayloadHash
    : role === "verifier" ? computeVerifierEvidenceBoundProposalPayloadHash
      : role === "auditor" ? computeAuditorEvidenceBoundProposalPayloadHash
        : role === "maintainer" ? computeMaintainerEvidenceBoundProposalPayloadHash
          : computeRecognitionEvidenceBoundProposalPayloadHash;
  const boundActionPayloadHash = bind(basePayloadHash, proposal.evidenceVerifierAuthorizationId,
    proposal.evidenceVerifierKeyIdCommitment, proposal.activePolicyCommitment, proposal.activePolicyVersion);
  const verify = role === "issuer" ? verifyIssuerProposalEvidenceSignature
    : role === "verifier" ? verifyVerifierProposalEvidenceSignature
      : role === "auditor" ? verifyAuditorProposalEvidenceSignature
        : role === "maintainer" ? verifyMaintainerProposalEvidenceSignature
          : verifyRecognitionProposalEvidenceSignature;
  if (!verify(key.publicKey, ledger.registryId, proposal.evidenceVerifierKeyIdCommitment,
    boundActionPayloadHash, {
      announcement: proposal.verifierSignatureAnnouncement,
      response: proposal.verifierSignatureResponse,
    })) {
    throw new Error("Proposal evidence verifier signature is invalid");
  }
  return {
    role,
    authorizationId,
    eventHash: hex(proposal.proposalGovernanceEventHash),
    evidenceCommitment: hex(proposal.evidenceCommitment),
    verifierAuthorizationId: hex(proposal.evidenceVerifierAuthorizationId),
    verifierDidCommitment: hex(proposal.evidenceVerifierDidCommitment),
    verifierKeyIdCommitment: hex(proposal.evidenceVerifierKeyIdCommitment),
    verifierSuite: hex(proposal.evidenceVerifierSuite),
    policyCommitment: hex(proposal.activePolicyCommitment),
    policyVersion: proposal.activePolicyVersion.toString(),
    verifierPublicKey: { x: key.publicKey.x.toString(), y: key.publicKey.y.toString() },
    verifierSignature: {
      announcement: {
        x: proposal.verifierSignatureAnnouncement.x.toString(),
        y: proposal.verifierSignatureAnnouncement.y.toString(),
      },
      response: proposal.verifierSignatureResponse.toString(),
    },
    subjectDidCommitment: hex(subjectDidCommitment),
    grantPolicyIdCommitment: hex(authorization.policyId),
    proposedAtSequence: authorization.proposedAtSequence.toString(),
    boundActionPayloadHash: hex(boundActionPayloadHash),
    signatureVerified: true,
  };
}
